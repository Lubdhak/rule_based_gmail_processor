# Gmail Automation Processor

This application helps automate email processing in Gmail using rules defined in a JSON file.

## Features

- Fetch emails from Gmail
- Store emails in a local SQLite database
- Apply rules to process emails (mark as read/unread, move to labels)
- Customizable rules with multiple conditions

## Setup

1. Clone this repository
2. Install dependencies: `pip3 install -r requirements.txt`
3. Create a Google Cloud Project and enable Gmail API
4. Download OAuth 2.0 credentials and save as `credentials.json`
5. Run the application: `python3 app.py`
6. Run the tests: `python3 -m unittest app_test.py`

## Configuration

Create a `rules.json` file with your processing rules. Example:

```json
[
    {
        "predicate": "any",
        "conditions": [
            {
                "field": "from",
                "predicate": "contains",
                "value": "newsletter"
            },
            {
                "field": "subject",
                "predicate": "contains",
                "value": "promotion"
            }
        ],
        "actions": [
            {
                "type": "move message",
                "value": "Newsletters"
            }
        ]
    }
]


+----------------+---------------------+---------------------------------+--------------------------------+
|  Field         |  Predicate          |  Value Format                   |  Example                       |
+----------------+---------------------+---------------------------------+--------------------------------+
|  from          |  contains           |  Any string                     |  "amazon"                      |
|                |  does not contain   |                                 |  "spam@"                       |
|                |  equals             |                                 |  "notifications@github.com"    |
|                |  does not equal     |                                 |  "newsletter@"                 |
+----------------+---------------------+---------------------------------+--------------------------------+
|  to            |  contains           |  Any string                     |  "me@mycompany.com"            |
|                |  does not contain   |                                 |  "external@"                   |
|                |  equals             |                                 |  "inbox@mydomain.com"          |
|                |  does not equal     |                                 |  "archive@"                    |
+----------------+---------------------+---------------------------------+--------------------------------+
|  subject       |  contains           |  Any string                     |  "URGENT"                      |
|                |  does not contain   |                                 |  "[SPAM]"                      |
|                |  equals             |                                 |  "Meeting Invitation"          |
|                |  does not equal     |                                 |  "Weekly Digest"               |
+----------------+---------------------+---------------------------------+--------------------------------+
|  message       |  contains           |  Any string                     |  "invoice attached"            |
|                |  does not contain   |                                 |  "unsubscribe"                 |
|                |  equals             |                                 |  "Your order confirmation"     |
|                |  does not equal     |                                 |  "Password reset"              |
+----------------+---------------------+---------------------------------+--------------------------------+
|  received_date |  less than          |  "X days" or "X months"         |  "30 days"                     |
|                |  greater than       |                                 |  "3 months"                    |
+----------------+---------------------+---------------------------------+--------------------------------+
|  ACTIONS       |                     |                                 |                                |
+----------------+---------------------+---------------------------------+--------------------------------+
|  mark as read  |  (no value needed)  |                                 |                                |
|  mark as unread|  (no value needed)  |                                 |                                |
|  move message  |  label name         |  Any existing/new label name    |  "Important"                   |
+----------------+---------------------+---------------------------------+--------------------------------+
|  RULE OPTIONS  |                     |                                 |                                |
+----------------+---------------------+---------------------------------+--------------------------------+
|  predicate     |  all                |  All conditions must match      |                                |
|                |  any                |  Any condition can match        |                                |
+----------------+---------------------+---------------------------------+--------------------------------+