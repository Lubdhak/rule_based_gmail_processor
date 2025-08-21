# Gmail Automation Processor

This application automates Gmail email processing using rules defined in
a JSON file.\
It fetches unread emails, stores them in a SQLite database, evaluates
them against rules, and performs Gmail actions such as marking as
read/unread or moving to a label.

------------------------------------------------------------------------

## Features

-   **OAuth2 Authentication** with Gmail API (using `token.json` +
    client credentials).
-   **Async Fetching**: Emails are fetched concurrently with retry
    handling (rate-limit aware).
-   **Local SQLite Storage** (`emails.db`):
    -   Stores fetched emails.
    -   Tracks last sync date to fetch only new/unread emails since the
        last run.
    -   Prevents re-processing of already processed emails.
-   **Rule Engine**:
    -   Supports multiple conditions (on sender, recipient, subject,
        message, received date).
    -   Supports multiple actions (mark read/unread, move to label).
    -   Rules can use `any` (OR) or `all` (AND) predicates.
-   **Action Executor**:
    -   Marks emails read/unread.
    -   Moves emails to labels (auto-creates labels if not present).
-   **Extensible**: Easy to add more conditions/actions.

------------------------------------------------------------------------

## Setup

1.  Clone this repository.

2.  Install dependencies:

    ``` bash
    pip3 install -r requirements.txt
    ```

3.  Create a Google Cloud Project and enable **Gmail API**.

4.  Download **OAuth 2.0 Client Credentials** and save them as\
    `client_secret_XXXX.json` (filename configurable in `main()`).

5.  Run the application:

    ``` bash
    python3 app.py
    ```

6.  First run will prompt Google login → generates `token.json`.

7.  Run tests (if available):

    ``` bash
    python3 -m unittest app_test.py
    ```

------------------------------------------------------------------------

## Configuration

Create a `rules.json` file with your processing rules. Example:

``` json
[
  {
    "predicate": "any",
    "conditions": [
      { "field": "from", "predicate": "contains", "value": "newsletter" },
      { "field": "subject", "predicate": "contains", "value": "promotion" }
    ],
    "actions": [
      { "type": "move message", "value": "Newsletters" }
    ]
  }
]
```

------------------------------------------------------------------------

## Rules Demystified

  --------------------------------------------------------------------------------------
  Field               Predicate       Value Format        Example
  ------------------- --------------- ------------------- ------------------------------
  **from**            contains        string              `"amazon"`

                      does not        string              `"spam@"`
                      contain                             

                      equals          string              `"notifications@github.com"`

                      does not equal  string              `"newsletter@"`

  **to**              contains        string              `"me@mycompany.com"`

                      does not        string              `"external@"`
                      contain                             

                      equals          string              `"inbox@mydomain.com"`

                      does not equal  string              `"archive@"`

  **subject**         contains        string              `"URGENT"`

                      does not        string              `"[SPAM]"`
                      contain                             

                      equals          string              `"Meeting Invitation"`

                      does not equal  string              `"Weekly Digest"`

  **message**         contains        string              `"invoice attached"`

                      does not        string              `"unsubscribe"`
                      contain                             

                      equals          string              `"Your order confirmation"`

                      does not equal  string              `"Password reset"`

  **received_date**   less than       `"X days"` or       `"30 days"`
                                      `"X months"`        

                      greater than    `"X days"` or       `"3 months"`
                                      `"X months"`        
  --------------------------------------------------------------------------------------

### Actions

-   **mark as read**\
-   **mark as unread**\
-   **move message** → requires `"value"` as label name (auto-created if
    missing)

### Rule Options

-   **predicate = all** → All conditions must match.\
-   **predicate = any** → At least one condition must match.

------------------------------------------------------------------------

## How It Works

1.  **Authentication**:\
    Uses `client_secret_*.json` + cached `token.json` for OAuth2.
2.  **Fetching**:
    -   Fetches emails concurrently (`asyncio + aiohttp`).\
    -   Uses last synced `received_date` to avoid re-fetching old
        emails.\
    -   Only fetches **UNREAD + INBOX** emails by default.
3.  **Storage**:
    -   Emails saved in `emails.db`.\
    -   Tracks `condition` field → ensures idempotency (no
        re-processing).
4.  **Rule Matching**:
    -   Each email checked against rules in `rules.json`.\
    -   Supports flexible conditions and predicates.\
    -   Executes matched actions via Gmail API.
5.  **Processing**:
    -   Marks processed emails with the applied condition.\
    -   Logs each action (`logger.info`).

------------------------------------------------------------------------

## Scope Improvements (Future Enhancements)

-   More parallelism for large inboxes.\
-   Smarter error handling & exponential backoff for API limits.\
-   Support for HTML parsing and multi-part emails.\
-   Web dashboard for managing rules dynamically.\
-   Support for additional Gmail actions (delete, reply, forward).

------------------------------------------------------------------------

## Summary

This is a **minimalistic yet powerful** setup to apply rule-based
actions on Gmail using the Gmail API:

-   Authenticates with Gmail via OAuth2.\
-   Fetches only **new unread emails** since last sync.\
-   Processes emails in parallel.\
-   Stores & tracks processed emails in SQLite (`emails.db`).\
-   Executes rule-based Gmail actions (`mark as read`, `mark as unread`,
    `move to label`).\
-   Modular design with clear responsibilities:
    -   `GmailClient` → fetch & parse emails.\
    -   `EmailRepository` → DB operations.\
    -   `GmailActionExecutor` → Gmail API actions.\
    -   `RuleEngine` → applies conditions & actions.\
    -   `EmailProcessor` → orchestrates the workflow.
