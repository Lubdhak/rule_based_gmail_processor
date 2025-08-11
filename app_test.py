import unittest
from unittest.mock import MagicMock, patch
from datetime import datetime, timedelta
import sqlite3
import json
import os
import base64
from app import GmailClient, EmailRepository, RuleEngine, GmailActionExecutor

class EmailMocker:
 @staticmethod
 def create_mock_email(**kwargs):
  default_email = {
   'gmail_id': f'mock_{hash(str(datetime.now()))}',
   'thread_id': f'thread_{hash(str(datetime.now()))}',
   'labels': ['INBOX'],
   'snippet': 'Mock email snippet',
   'internal_date': str(int(datetime.now().timestamp() * 1000)),
   'is_read': False,
   'from': 'mock.sender@example.com',
   'to': 'mock.recipient@example.com',
   'subject': 'Mock Email Subject',
   'message': 'Mock email body content',
   'received_date': datetime.now().isoformat()
  }
  default_email.update(kwargs)
  return default_email

 @staticmethod
 def create_mock_email_list(count=5):
  return [EmailMocker.create_mock_email() for _ in range(count)]

 @staticmethod
 def create_mock_gmail_api_response(count=5):
  return {
   'messages': [{'id': f'mock_{i}', 'threadId': f'thread_{i}'} for i in range(count)]
  }

 @staticmethod
 def create_mock_gmail_message(**kwargs):
  default_msg = {
   'id': 'mock_123',
   'threadId': 'thread_123',
   'labelIds': ['INBOX'],
   'snippet': 'Mock snippet',
   'internalDate': str(int(datetime.now().timestamp() * 1000)),
   'raw': base64.urlsafe_b64encode(b'Mock raw email content').decode('ascii')
  }
  default_msg.update(kwargs)
  return default_msg

class TestGmailClient(unittest.TestCase):
 @patch('app.build')
 @patch('app.Credentials')
 @patch('app.InstalledAppFlow')
 def test_authenticate(self, mock_flow, mock_creds, mock_build):
  client = GmailClient('token.json', 'credentials.json')
  self.assertIsNotNone(client.service)

 @patch.object(GmailClient, '_authenticate')
 def test_fetch_emails(self, mock_auth):
  mock_service = MagicMock()
  mock_service.users().messages().list().execute.return_value = EmailMocker.create_mock_gmail_api_response(1)
  mock_service.users().messages().get().execute.return_value = EmailMocker.create_mock_gmail_message()
  mock_auth.return_value = mock_service
  
  client = GmailClient('token.json', 'credentials.json')
  emails = client.fetch_emails()
  self.assertEqual(len(emails), 1)
  self.assertTrue(emails[0]['gmail_id'].startswith('mock_'))

class TestEmailRepository(unittest.TestCase):
 def setUp(self):
  self.db_file = 'test_emails.db'
  if os.path.exists(self.db_file):
   os.remove(self.db_file)
  self.repo = EmailRepository(self.db_file)
  self.mock_email = EmailMocker.create_mock_email()
  
 def tearDown(self):
  if os.path.exists(self.db_file):
   os.remove(self.db_file)

 def test_init_db(self):
  conn = sqlite3.connect(self.db_file)
  cursor = conn.cursor()
  cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='emails'")
  result = cursor.fetchone()
  conn.close()
  self.assertIsNotNone(result)
  self.assertEqual(result[0], 'emails')
        
 def test_save_and_get_emails(self):
  save_result = self.repo.save_email(self.mock_email)
  self.assertTrue(save_result)
  
  emails = self.repo.get_emails()
  self.assertEqual(len(emails), 1)
  self.assertEqual(emails[0]['gmail_id'], self.mock_email['gmail_id'])

class TestRuleEngine(unittest.TestCase):
 def setUp(self):
  self.engine = RuleEngine()
  self.test_email = EmailMocker.create_mock_email(
   subject='Important message',
   from_email='test@example.com'
  )
    
 def test_validate_rules(self):
  valid_rule = {
   "predicate": "any",
   "conditions": [
    {
     "field": "from",
     "predicate": "contains",
     "value": "example"
    }
   ],
   "actions": [
    {
     "type": "mark as read"
    }
   ]
  }
  rules = self.engine._validate_rules([valid_rule])
  self.assertEqual(len(rules), 1)
  
 def test_evaluate_condition(self):
  condition = {
   "field": "subject",
   "predicate": "contains",
   "value": "Important"
  }
  self.assertTrue(self.engine._evaluate_condition(condition, self.test_email))
  
  old_date_email = self.test_email.copy()
  old_date_email['received_date'] = (datetime.now() - timedelta(days=30)).isoformat()
  condition = {
   "field": "received_date",
   "predicate": "greater than",
   "value": "15 days"
  }
  self.assertTrue(self.engine._evaluate_condition(condition, old_date_email))

class TestGmailActionExecutor(unittest.TestCase):
 @patch('app.build')
 def test_mark_as_read(self, mock_build):
  mock_service = MagicMock()
  mock_build.return_value = mock_service
  
  executor = GmailActionExecutor(mock_service)
  self.assertTrue(executor.mark_as_read('mock_123'))
  mock_service.users().messages().modify.assert_called_once()

if __name__ == '__main__':
 unittest.main()