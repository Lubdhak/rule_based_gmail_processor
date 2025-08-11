import os,json,sqlite3,re,logging,base64,email
from datetime import datetime,timedelta
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from email.utils import parsedate_to_datetime

logging.basicConfig(level=logging.INFO)
logger=logging.getLogger(__name__)

class GmailClient:
	SCOPES=['https://www.googleapis.com/auth/gmail.modify']
	
	def __init__(self,token_file,cred_file):
		self.token_file=token_file
		self.credentials_file=cred_file
		self.service=self._authenticate()
	
	def _authenticate(self):
		creds=None
		if os.path.exists(self.token_file):
			creds=Credentials.from_authorized_user_file(self.token_file,self.SCOPES)
		if not creds or not creds.valid:
			if creds and creds.expired and creds.refresh_token:
				creds.refresh(Request())
			else:
				flow=InstalledAppFlow.from_client_secrets_file(self.credentials_file,self.SCOPES)
				creds=flow.run_local_server(port=0)
			with open(self.token_file,'w')as token:token.write(creds.to_json())
		return build('gmail','v1',credentials=creds)
	
	def fetch_emails(self,max_results=10,mock=False):
		try:
			if mock:
				return EmailMocker.create_mock_email_list(max_results)
			results=self.service.users().messages().list(userId='me',labelIds=['INBOX'],maxResults=max_results).execute()
			emails=[]
			for msg in results.get('messages',[]):
				try:
					email_data=self.service.users().messages().get(userId='me',id=msg['id'],format='raw').execute()
					email_dict=self._parse_email(email_data)
					if email_dict:emails.append(email_dict)
				except Exception as e:logger.error(f"Error processing email {msg['id']}:{e}")
			return emails
		except Exception as e:logger.error(f"Error fetching emails:{e}");return[]
	
	def _parse_email(self,email_data):
		try:
			msg_str=base64.urlsafe_b64decode(email_data['raw'].encode('ASCII'))
			mime_msg=email.message_from_bytes(msg_str)
			email_dict={'gmail_id':email_data['id'],'thread_id':email_data.get('threadId'),'labels':email_data.get('labelIds',[]),'snippet':email_data.get('snippet',''),'internal_date':email_data.get('internalDate'),'is_read':'UNREAD'not in email_data.get('labelIds',[]),'from':'','to':'','subject':'','message':'','received_date':None}
			for header in ['From','To','Subject','Date']:
				if header in mime_msg:
					if header=='Date':
						try:email_dict['received_date']=parsedate_to_datetime(mime_msg[header]).replace(tzinfo=None).isoformat()
						except:email_dict['received_date']=None
					else:email_dict[header.lower()]=mime_msg[header]
			try:email_dict['message']=self._get_email_body(mime_msg)
			except:email_dict['message']=''
			return email_dict
		except Exception as e:logger.error(f"Error parsing email:{e}");return None
	
	def _get_email_body(self,msg):
		try:
			if msg.is_multipart():
				for part in msg.walk():
					if part.get_content_type()=='text/plain':return part.get_payload(decode=True).decode('utf-8',errors='ignore')
			return msg.get_payload(decode=True).decode('utf-8',errors='ignore')
		except:return''

class EmailRepository:
	def __init__(self,db_file='emails.db'):
		self.db_file=db_file
		self._init_db()
	
	def _init_db(self):
		conn=sqlite3.connect(self.db_file)
		conn.execute('''CREATE TABLE IF NOT EXISTS emails(id INTEGER PRIMARY KEY AUTOINCREMENT,gmail_id TEXT UNIQUE,thread_id TEXT,labels TEXT,snippet TEXT,internal_date TEXT,is_read INTEGER,from_email TEXT,to_email TEXT,subject TEXT,message TEXT,received_date TEXT)''')
		conn.commit();conn.close()
	
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
			cursor.execute('SELECT*FROM emails ORDER BY received_date DESC LIMIT?',(limit,))
			emails=[dict(zip([column[0]for column in cursor.description],row))for row in cursor.fetchall()]
			for email_dict in emails:email_dict['labels']=json.loads(email_dict['labels'])
			conn.close();return emails
		except Exception as e:logger.error(f"Error fetching emails:{e}");return[]

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

class EmailMocker:
	@staticmethod
	def create_mock_email(**kwargs):
		default_email={
			'gmail_id':'mock_'+str(hash(str(datetime.now()))),
			'thread_id':'thread_'+str(hash(str(datetime.now()))),
			'labels':['INBOX'],
			'snippet':'This is a mock email snippet',
			'internal_date':str(int(datetime.now().timestamp()*1000)),
			'is_read':False,
			'from':'mock.sender@example.com',
			'to':'mock.recipient@example.com',
			'subject':'Mock Email Subject',
			'message':'This is the body of the mock email',
			'received_date':datetime.now().isoformat()
		}
		default_email.update(kwargs)
		return default_email

	@staticmethod
	def create_mock_email_list(count=5):
		return [EmailMocker.create_mock_email()for _ in range(count)]

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
					print(email_data['subject'])
					print(rule)
					return True
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
	
	def fetch_and_store_emails(self,max_results=10,mock=False):
		try:
			emails=self.gmail_client.fetch_emails(max_results,mock)
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
			processed_count=0
			for email_data in self.repository.get_emails():
				if email_data and self.rule_engine.process_email(email_data,self.action_executor):
					processed_count+=1
			return processed_count
		except Exception as e:logger.error(f"Error processing emails:{e}");return 0

def main():
	processor=EmailProcessor('./token.json','./credentials.json')
	print("Fetching emails...")
	if processor.fetch_and_store_emails(max_results=50,mock=False):print("Emails fetched successfully.")
	else:print("Failed to fetch emails.")
	print("Loading rules...")
	if processor.load_rules('./rules.json'):print("Rules loaded successfully.")
	else:print("Failed to load rules.")
	print("Processing emails...")
	print(f"Processed {processor.process_emails()} emails.")

if __name__=='__main__':main()