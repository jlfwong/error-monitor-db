import httplib2
import pprint

from apiclient.discovery import build
from apiclient.errors import HttpError

from oauth2client.client import AccessTokenRefreshError
from oauth2client.client import flow_from_clientsecrets
from oauth2client.file import Storage
from oauth2client import tools

PROJECT_NUMBER = '124072386181'

class BigQueryUtil(object):
    def __init__(self):
        FLOW = flow_from_clientsecrets('client_secrets.json',
                                       scope='https://www.googleapis.com/auth/bigquery')

        storage = Storage('bigquery_credentials.dat')
        credentials = storage.get()

        if credentials is None or credentials.invalid:
          # Run oauth2 flow with default arguments.
          credentials = tools.run_flow(
              FLOW, storage,
              tools.argparser.parse_args(["--noauth_local_webserver"]))

        http = httplib2.Http()
        http = credentials.authorize(http)

        self.bigquery_service = build('bigquery', 'v2', http=http)

    def run_query(self, sql):
        try:
            # Create a query statement and query request object
            query_data = {'query': sql}
            query_request = self.bigquery_service.jobs()

            # Make a call to the BigQuery API
            query_response = query_request.query(projectId=PROJECT_NUMBER,
                                                 body=query_data).execute()

        except HttpError as err:
            print 'Error:', pprint.pprint(err.content)
            return None

        except AccessTokenRefreshError:
            print ("Credentials have been revoked or expired, please re-run"
                    "the application to re-authorize")
            return None
            

        return query_response['rows']
