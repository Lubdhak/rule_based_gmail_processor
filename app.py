import os,json,sqlite3,re,logging,base64,email
from datetime import datetime,timedelta
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from email.utils import parsedate_to_datetime
import asyncio
import aiohttp

logging.basicConfig(level=logging.INFO)
logger=logging.getLogger(__name__)

class GmailClient:
	SCOPES = ['https://www.googleapis.com/auth/gmail.modify']
    
	def __init__(self, token_file, cred_file):
		self.token_file = token_file
		self.credentials_file = cred_file
		self.service = self._authenticate()
		self.list_url = 'https://gmail.googleapis.com/gmail/v1/users/me/messages'
	
	def _authenticate(self):
		creds = None
		if os.path.exists(self.token_file):
			try:
				creds = Credentials.from_authorized_user_file(self.token_file, self.SCOPES)
				if creds and creds.expired and creds.refresh_token:
					creds.refresh(Request())
			except Exception as e:
				logger.warning(f"Token refresh failed: {e}")
				os.unlink(self.token_file)
				creds = None
		if not creds or not creds.valid:
			flow = InstalledAppFlow.from_client_secrets_file(self.credentials_file, self.SCOPES)
			creds = flow.run_local_server(port=0)
			with open(self.token_file, 'w') as token:
				token.write(creds.to_json())
		return build('gmail', 'v1', credentials=creds)
	
	async def fetch_emails(self, max_results=10):
		try:
			creds = self.service._http.credentials
			if creds.expired: creds.refresh(Request())
			headers = {"Authorization": f"Bearer {creds.token}"}
			async with aiohttp.ClientSession(headers=headers) as session:
				params = {"maxResults": max_results,"labelIds": ["UNREAD", "INBOX"]}
				synced_till = EmailRepository().max_sync_date()
				if synced_till: params['q'] = f"after:{synced_till}"
				async with session.get(self.list_url, params=params) as resp:
					data = await resp.json()
					message_ids = [msg['id'] for msg in data.get('messages', [])]
				semaphore = asyncio.Semaphore(3)
				
				async def fetch_with_limit(msg_id):
					async with semaphore:
						await asyncio.sleep(0.1)
						return await self._fetch_single_email(session, msg_id)

				tasks = [fetch_with_limit(msg_id) for msg_id in message_ids]
				results = await asyncio.gather(*tasks)
				return [r for r in results if r]
		except Exception as e: logger.error(f"Error fetching emails: {e}"); return []

	async def _fetch_single_email(self, session, msg_id, retry_count=0):
		try:
			url = f"{self.list_url}/{msg_id}"
			async with session.get(url, params={"format": "full"}) as resp:
				if resp.status == 429 and retry_count < 3:
					wait_time = 2 ** retry_count
					logger.warning(f"Rate limited for {msg_id}, waiting {wait_time}s (attempt {retry_count + 1})")
					await asyncio.sleep(wait_time)
					return await self._fetch_single_email(session, msg_id, retry_count + 1)
				if resp.status != 200: logger.warning(f"Failed to fetch email {msg_id}: HTTP {resp.status}"); return
				
				email_data = await resp.json()
				if 'error' in email_data:
					error_code = email_data['error'].get('code', 'unknown')
					if error_code == 429 and retry_count < 3:
						wait_time = 2 ** retry_count
						logger.warning(f"API rate limit for {msg_id}, waiting {wait_time}s")
						await asyncio.sleep(wait_time)
						return await self._fetch_single_email(session, msg_id, retry_count + 1)
					else: logger.error(f"API error for {msg_id}: {email_data['error']}"); return
				return self._parse_email(email_data)
		except Exception as e: logger.error(f"Error fetching email {msg_id}: {e}")

	def _parse_email(self, email_data):
		try:
			payload = email_data.get('payload', {})
			headers = {h['name'].lower(): h['value'] for h in payload.get('headers', [])}
			labels = email_data.get('labelIds', [])
			internal_date = email_data.get('internalDate',0)

			return {
				'gmail_id': email_data['id'],
				'thread_id': email_data.get('threadId', 'unknown_thread'),
				'labels': labels,
				'snippet': email_data.get('snippet', ''),
				'internal_date': internal_date,
				'is_read': 'UNREAD' not in labels,
				'from': headers.get('from', ''),
				'to': headers.get('to', ''),
				'subject': headers.get('subject', ''),
				'message': self._get_email_body(payload) or '',
				'received_date': self._parse_date(headers.get('date')) or ''
				}
		except Exception as e:
			print(f"Problematic email data: {email_data}") 
			logger.error(f"Error parsing email: {e}")
			return None

	def _get_email_body(self, payload):
		try:
			if 'parts' in payload:
				for part in payload.get('parts'):
					if part['mimeType'] == 'text/plain':
						data = part['body'].get('data', '')
						if data: return base64.urlsafe_b64decode(data).decode('utf-8')
			return ''
		except: return ''

	def _parse_date(self, date_str):
		try: return parsedate_to_datetime(date_str).isoformat() if date_str else None
		except: return ''


class EmailRepository:
	def __init__(self,db_file='emails.db'):
		self.db_file=db_file
		self._init_db()
	
	def _init_db(self):
		conn=sqlite3.connect(self.db_file)
		conn.execute('''CREATE TABLE IF NOT EXISTS emails(id INTEGER PRIMARY KEY AUTOINCREMENT,gmail_id TEXT UNIQUE,thread_id TEXT,labels TEXT,snippet TEXT,internal_date TEXT,is_read INTEGER,from_email TEXT,to_email TEXT,subject TEXT,message TEXT,received_date TEXT, condition TEXT)''')
		conn.commit();conn.close()

	def max_sync_date(self):
		try:
			conn = sqlite3.connect(self.db_file)
			cursor = conn.cursor()
			cursor.execute("SELECT strftime('%Y/%m/%d', substr(received_date, 1, 19) ) as gmail_date_format FROM emails WHERE received_date IS NOT NULL AND received_date != '' ORDER BY received_date DESC LIMIT 1")
			result = cursor.fetchone()
			conn.close()
			if result: return result[0]
		except Exception as e: logger.error(f"Error getting max sync date: {e}");
	
	def save_email(self,email_data):
		try:
			conn=sqlite3.connect(self.db_file)
			conn.execute('''INSERT OR REPLACE INTO emails(gmail_id,thread_id,labels,snippet,internal_date,is_read,from_email,to_email,subject,message,received_date)VALUES(?,?,?,?,?,?,?,?,?,?,?)''',(email_data['gmail_id'],email_data['thread_id'],json.dumps(email_data['labels']),email_data['snippet'],email_data['internal_date'],int(email_data['is_read']),email_data['from'],email_data['to'],email_data['subject'],email_data['message'],email_data['received_date']))
			conn.commit();conn.close();return True
		except Exception as e:logger.error(f"Error saving email:{e}");return False
	
	def get_emails(self,limit=100):
		try:
			conn=sqlite3.connect(self.db_file)
			cursor=conn.cursor()
			cursor.execute('SELECT*FROM emails WHERE condition is NULL ORDER BY received_date DESC LIMIT?',(limit,))
			emails=[dict(zip([column[0]for column in cursor.description],row))for row in cursor.fetchall()]
			for email_dict in emails:email_dict['labels']=json.loads(email_dict['labels'])
			conn.close();return emails
		except Exception as e:logger.error(f"Error fetching emails:{e}");return[]
	
	def mark_as_processed(self,email_data,condition):
		try:
			conn = sqlite3.connect(self.db_file)
			cursor = conn.cursor()
			cursor.execute('UPDATE emails SET condition = ? WHERE gmail_id = ? AND thread_id = ?',(condition, email_data['gmail_id'], email_data['thread_id']))
			conn.commit()
			conn.close()
		except Exception as e: logger.error(f"Error marking email as processed: {e}")


class GmailActionExecutor:
	def __init__(self,gmail_service):
		self.service=gmail_service
	
	def mark_as_read(self,email_id):
		try:
			self.service.users().messages().modify(userId='me',id=email_id,body={'removeLabelIds':['UNREAD']}).execute()
			return True
		except Exception as e:logger.error(f"Error marking read:{e}");return False
	
	def mark_as_unread(self,email_id):
		try:
			self.service.users().messages().modify(userId='me',id=email_id,body={'addLabelIds':['UNREAD']}).execute()
			return True
		except Exception as e:logger.error(f"Error marking unread:{e}");return False
	
	def move_message(self,email_id,label_name):
		try:
			label_id=self._get_or_create_label(label_name)
			if not label_id:return False
			self.service.users().messages().modify(userId='me',id=email_id,body={'addLabelIds':[label_id],'removeLabelIds':['INBOX']}).execute()
			return True
		except Exception as e:logger.error(f"Error moving message:{e}");return False
	
	def _get_or_create_label(self,label_name):
		try:
			labels=self.service.users().labels().list(userId='me').execute().get('labels',[])
			for label in labels:
				if label['name'].lower()==label_name.lower():return label['id']
			created=self.service.users().labels().create(userId='me',body={'name':label_name,'labelListVisibility':'labelShow','messageListVisibility':'show'}).execute()
			return created['id']
		except Exception as e:logger.error(f"Error handling label:{e}");return None


class RuleEngine:
	def __init__(self,rules_file='rules.json'):
		self.rules_file=rules_file
		self.rules=self._load_rules()
	
	def _load_rules(self):
		try:
			if os.path.exists(self.rules_file):
				with open(self.rules_file,'r')as f:return self._validate_rules(json.load(f))
			return[]
		except Exception as e:logger.error(f"Error loading rules:{e}");return[]
	
	def _validate_rules(self,rules):
		valid_rules=[]
		for rule in rules:
			try:
				if not all(k in rule for k in['conditions','actions','predicate']):continue
				if rule['predicate'].lower()not in{'all','any'}:continue
				valid_conditions=[]
				for cond in rule['conditions']:
					if not all(k in cond for k in['field','predicate','value']):continue
					field=cond['field'].lower()
					if field not in{'from','to','subject','message','received_date'}:continue
					predicate=cond['predicate'].lower()
					if field=='received_date':
						if predicate not in{'less than','greater than'}:continue
						if not re.match(r'^\d+\s+(day|month)s?$',cond['value'].lower()):continue
					else:
						if predicate not in{'contains','does not contain','equals','does not equal'}:continue
					valid_conditions.append(cond)
				if not valid_conditions:continue
				valid_actions=[]
				for action in rule['actions']:
					if not all(k in action for k in['type']):continue
					action_type=action['type'].lower()
					if action_type not in{'mark as read','mark as unread','move message'}:continue
					if action_type=='move message'and'value'not in action:continue
					valid_actions.append(action)
				if valid_actions:valid_rules.append({'predicate':rule['predicate'].lower(),'conditions':valid_conditions,'actions':valid_actions})
			except Exception as e:logger.warning(f"Skipping invalid rule:{e}")
		return valid_rules
	
	def process_email(self,email_data,action_executor):
		try:
			if not email_data or'received_date'not in email_data:return False
			for rule in self.rules:
				if self._evaluate_rule(rule,email_data):
					self._execute_actions(rule['actions'],email_data['gmail_id'],action_executor)
					cond = rule['conditions'][0]
					print(f"● '{email_data['subject']}' → {cond['field']} {cond['predicate']} '{cond['value']}' → {rule['actions'][0]['type']}")
					return str(cond)
			return False
		except Exception as e:logger.error(f"Error processing email:{e}");return False
	
	def _evaluate_rule(self,rule,email_data):
		if rule['predicate']=='any':return any(self._evaluate_condition(cond,email_data)for cond in rule['conditions'])
		return all(self._evaluate_condition(cond,email_data)for cond in rule['conditions'])
	
	def _evaluate_condition(self,condition,email_data):
		field=condition['field'].lower()
		predicate=condition['predicate'].lower()
		value=condition['value']
		email_value=str(email_data.get(field,''))
		if field=='received_date':return self._evaluate_date_condition(email_value,predicate,value)
		return self._evaluate_text_condition(email_value,predicate,value)
	
	def _evaluate_text_condition(self,email_value,predicate,value):
		email_value=email_value.lower();value=value.lower()
		if predicate=='contains':return value in email_value
		elif predicate=='does not contain':return value not in email_value
		elif predicate=='equals':return email_value==value
		elif predicate=='does not equal':return email_value!=value
		return False
	
	def _evaluate_date_condition(self,email_date,predicate,value):
		if not email_date:return False
		try:
			email_dt=datetime.fromisoformat(email_date)
			if email_dt.tzinfo:email_dt=email_dt.replace(tzinfo=None)
			now=datetime.now()
			num,unit=re.match(r'(\d+)\s+(day|month)s?',value.lower()).groups()
			delta=timedelta(days=int(num))if unit=='day'else timedelta(days=int(num)*30)
			if predicate=='less than':return email_dt>(now-delta)
			elif predicate=='greater than':return email_dt<(now-delta)
			return False
		except Exception as e:logger.error(f"Error evaluating date:{e}");return False
	
	def _execute_actions(self,actions,email_id,action_executor):
		try:
			for action in actions:
				action_type=action['type'].lower()
				if action_type=='mark as read':action_executor.mark_as_read(email_id)
				elif action_type=='mark as unread':action_executor.mark_as_unread(email_id)
				elif action_type=='move message':action_executor.move_message(email_id,action['value'])
			return True
		except Exception as e:logger.error(f"Error executing actions:{e}");return False


class EmailProcessor:
	def __init__(self,token_file,cred_file):
		self.gmail_client=GmailClient(token_file,cred_file)
		self.repository=EmailRepository()
		self.action_executor=GmailActionExecutor(self.gmail_client.service)
		self.rule_engine=RuleEngine()

	async def fetch_and_store_emails(self, max_results=10):
		try:
			emails = await self.gmail_client.fetch_emails(max_results)
			for email_data in emails:
				if email_data:self.repository.save_email(email_data)
			return True
		except Exception as e:logger.error(f"Error fetching emails:{e}");return False
	
	def load_rules(self,rules_file):
		try:
			self.rule_engine=RuleEngine(rules_file)
			return True
		except Exception as e:logger.error(f"Error loading rules:{e}");return False
	
	def process_emails(self):
		try:
			er = EmailRepository()
			processed_count=0
			for email_data in self.repository.get_emails():
				if email_data:
					condition = self.rule_engine.process_email(email_data,self.action_executor)
					if condition is not False:
						er.mark_as_processed(email_data, condition)
						processed_count+=1
			return processed_count
		except Exception as e:logger.error(f"Error processing emails:{e}");return 0


async def main():
 processor=EmailProcessor('./token.json','./client_secret_292773047087-ecoega11uhdhq0lkot6jua8qi79imdbc.apps.googleusercontent.com.json')
 print("Fetching emails...")
 if await processor.fetch_and_store_emails(max_results=50):print("Emails fetched successfully.")
 else:print("Failed to fetch emails.")
 print("Loading rules...")
 if processor.load_rules('./rules.json'):print("Rules loaded successfully.")
 else:print("Failed to load rules.")
 print("Processing emails...")
 print(f"Processed {processor.process_emails()} emails.")

if __name__=='__main__':
 asyncio.run(main())