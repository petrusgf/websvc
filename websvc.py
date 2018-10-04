#!/usr/bin/env python3
#
# simple webservice to lookup provided GET URI in
# malware database and return OK or BAD to caller.


from flask import Flask,request,jsonify
from flask_restful import Resource, Api
from sqlalchemy import create_engine

# API URL prefix/version string - don't include leading /
# here to mimic how flask routes URI paths.
API_PREFIX = 'urlinfo/1'


# http://docs.sqlalchemy.org/en/latest/core/engines.html#engine-creation-api
# http://docs.sqlalchemy.org/en/latest/core/engines.html#database-urls
# add echo=True to see SQL being executed in logs...
engine = create_engine('sqlite:///malware.db',
                       case_sensitive=False)
# http://flask.pocoo.org
app = Flask(__name__)


# https://flask-restful.readthedocs.io/en/latest/api.html
api = Api(app)


class CheckUrl(Resource):
    """Given URI path, respond accordingly."""
    
    @staticmethod
    def sql_query(sql='', params=''):
        """SQL query wrapper to avoid repeating error handling.

        pass in params as tuple for dynamic queries.
        """

        if sql:
            # TODO: add better exception handling
            query = None
            try:
                # Setup database connection and run query
                connection = engine.connect()

                if params:
                    # https://docs.python.org/3/library/sqlite3.html
                    # see also: https://xkcd.com/327/
                    query = connection.execute(sql, params)
                else:
                    query = connection.execute(sql)

                return query.cursor.fetchall()
            finally:
                if query:
                    query.cursor.close()
        else:
            # Don't hit database if no SQL provided
            pass

    # handle HTTP GET, receive full URI as path.
    # path will not have a leading /
    @app.route('/urlinfo/1', methods=["get"])

    def get(self, path):
        
        """Given URI path, respond based on content:

        If path == API_PREFIX, dump full list of malware URLs.

        If path == API_PREFIX + URI, parse URI string into
        {host:port} and {uri} and return reputation
        """
        # Enable access to API_PREFIX constant
        global API_PREFIX
        # Save some typing, support trailing / per HTTP spec
        api_path = [API_PREFIX, API_PREFIX + '/']
        # Start with empty result dict and no errors
        result = {'error': False}
        # Build list of args for sql_query which may or may not
        # contain tuple for dynamic queries.
        sql = []
        url = path.split('/')
        if path in api_path:
            # dump full list of malware URLs
            sql.append("select domain, uri from malware")
        elif path.startswith(API_PREFIX):
            # lookup specific URL reputation. we receive full URI
            try:
                # got /prefix/host:port/uri
                host, uri = url[2], '/' + '/'.join(url[3:])
            except IndexError:
                # got /prefix/host:port
                host, uri = url[2], '/'

            # Don't use string formatting, avoid sql injection!
            sql.append("select domain, uri, result from malware "
                       "where domain=(:host) and uri=(:uri)")
            sql.append((host, uri,))
        else:
            # bad query, return early
            result['error'] = True
            result['message'] = 'bad requst'
            return result, 400

        # Query the database
        output = self.sql_query(*sql)

        if path in api_path:
            # build up full list of malware URLs to return
            result['urls'] = [i[0] + i[1] for i in output]
        else:
            try:
                # output[row][column]
                # Columns: host:port|URI|reputation
                if len(path) > 2010:
                    #result= ('error: 414-Request-URI Too Long')
                    return result, 414
                else:
                    result['url'] = output[0][0] + output[0][1]
                    result['reputation'] = output[0][2]
            except IndexError as e:
                # fail open if URI is not in database
                result['url'] = host + uri
                result['reputation'] = 'OK'
                result['error'] = True
                result['message'] = 'passing since ' + \
                                    host + uri + \
                                    ' not found in database'

        return result, 200

    @app.route('/urlinfo/post', methods=["post"])
    def post():
        # Build list of args for sql_query which may or may not
        # contain tuple for dynamic queries.
        try:
            domain= request.json['domain']
            uri = request.json['uri']
            result = request.json['result']
            connection = engine.connect()
            sql=connection.execute("insert into malware(domain,uri,result) VALUES('%s','%s','%s')" %(domain,uri,result))
        except IndexError as e:
            print ("error to add website to the database.")
        return result, 200

# http://flask.pocoo.org/snippets/57/
# TODO: <path:path> passes the full URI, but we could compile a regex
# TODO: to ensure 'path' is really valid else just return HTTP 400.
api.add_resource(CheckUrl, '/<path:path>')


# Run everything if we're not being imported...
if __name__ == '__main__':
    app.run(host='0.0.0.0')

