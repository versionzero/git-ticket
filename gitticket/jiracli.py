#!/usr/bin/env python
# -*- coding:utf-8 -*-
import datetime
import os
import requests
from jira.client import JIRA
from gitticket.config import nested_access
from gitticket import config
from gitticket import ticket
from gitticket import util

#CONSUMER_KEY = 'Bq7A3PXEdgGeWy94VA'
#CONSUMER_SECRET = 'jWvtdn3tR4Q9vGn3USbQJZZHAnd7neXM'


# ISSUEURL = os.path.join(SITEBASE, '{name}/{repo}/issues/{issueid}')

# OAUTH_REQUEST = os.path.join(APIBASE, 'oauth/request_token')
# OAUTH_AUTH = os.path.join(APIBASE, 'oauth/authenticate')
# OAUTH_ACCESS = os.path.join(APIBASE, 'oauth/access_token')

# REPO = os.path.join(, 'repositories/{name}/{repo}')

PROJKEY = 'PORT-'
APIBASE = 'https://jira.uleth.ca/rest/api/2'
SITEBASE = 'https://jira.uleth.ca'
ISSUEURL = os.path.join(SITEBASE, '/issues/{issueid}')
# ISSUES = os.path.join(APIBASE, 'issues')
ISSUES = os.path.join(APIBASE, 'search?jql=assignee={username}')
ISSUE = os.path.join(ISSUES, '{issueid}')
ISSUE_COMMENTS = os.path.join(ISSUE, 'comments')
ISSUE_COMMENT = os.path.join(ISSUE_COMMENTS, '{commentid}')

# DATEFMT = "%Y-%m-%d %H:%M:%S%Z"
# 2013-06-24T11:54:04.000-0600
DATEFMT = "%Y-%m-%dT%H:%M:%S.%f"


# def authorize():
#     service = OAuth1Service(name='bitbucket', consumer_key=CONSUMER_KEY, consumer_secret=CONSUMER_SECRET,
#                          request_token_url=OAUTH_REQUEST,
#                          access_token_url=OAUTH_ACCESS,
#                          authorize_url=OAUTH_AUTH)
#     rtoken, rtokensecret = service.get_request_token(method='GET')
#     auth_url = service.get_authorize_url(rtoken)
#     print "Visit this url and copy&paste your PIN.\n{0}".format(auth_url)
#     pin = raw_input('Please enter your PIN:')
#     r = service.get_access_token('POST', request_token=rtoken, request_token_secret=rtokensecret,
#                                  data={'oauth_verifier': pin})
#     content = r.content
#     return content['oauth_token'], content['oauth_token_secret']

@util.memoize
def myJira():
    cfg = config.parseconfig()
    options = {
        'server': 'https://jira.uleth.ca'
    }
    return JIRA(options)


def issues(params={}):
    cfg = config.parseconfig()
    jira = myJira()
    if 'limit' not in params:
        params['limit'] = 50
    if 'state' in params:
        avail_states = ('new', 'open', 'resolved', 'on hold', 'invalid', 'duplicate', 'wontfix')
        if params['state'] not in avail_states:
            raise ValueError('Invarid query: available state are ({0})'.format(u', '.join(avail_states)))
        params['status'] = params.pop('state')
    if 'assignee' in params:
        params['responsible'] = params.pop('assignee')
    params['sort'] = params.pop('order', 'utc_last_updated')
    if params['sort'] == 'updated':
        params['sort'] = 'utc_last_updated'
    r = jira.search_issues('assignee=ben\u002eburnett')
    #for x in r: print x.fields.summary

    tickets = [_toticket(x) for x in r]
    return tickets

def issue(number, params={}):
    cfg = config.parseconfig()
    r = _request('get', ISSUE.format(issueid=number, **cfg), params=params)
    return _toticket(r)


def comments(number, params={}):
    cfg = config.parseconfig()
    cj = _request('get', ISSUE_COMMENTS.format(issueid=number, **cfg), {'limit':50})
    cj = [x for x in cj if x['content'] is not None]
    # commentは特殊。statusの変更がコメント化され、Web上では表示できるが、APIからは補足できない。
    comments = [ticket.Comment(number = x['comment_id'],
                               body = x['content'],
                               creator = nested_access(x, 'author_info.username'),
                               created = _todatetime(x['utc_created_on']),
                               updated = _todatetime(x['utc_updated_on'])) for x in cj]
    return comments



def add(params={}):
    comment = u'Available labels (select one): bug, enhancement, proposal, task\nAvailable priorities: trivial, minor, major, critical, blocker'
    template = ticket.template(('title', 'assignee', 'labels', 'priority', 'milestone', 'version', 'component', 'body'), comment=comment)
    val = util.inputwitheditor(template)
    if val == template:
        return
    data = _issuedata_from_template(val)
    cfg = config.parseconfig()
    r = _request('post', ISSUES.format(**cfg), data=data, params=params)
    return {'number': r['local_id'], 'html_url': ISSUEURL.format(issueid=r['local_id'], **cfg)}


def update(number, params={}):
    tic = issue(number, params)
    comment = u'Available labels (select one): bug, enhancement, proposal, task\nAvailable priorities: trivial, minor, major, critical, blocker'
    template = ticket.template(('title', 'assignee', 'labels', 'state', 'priority', 'milestone', 'version', 'component', 'body'), tic, comment=comment)
    val = util.inputwitheditor(template)
    if val == template:
        return
    data = _issuedata_from_template(val)
    cfg = config.parseconfig()
    _request('put', ISSUE.format(issueid=number, **cfg), data=data, params=params)


def changestate(number, state):
    if state == 'closed':
        state = 'resolved'
    avail_states = ('new', 'open', 'resolved', 'on hold', 'invalid', 'duplicate', 'wontfix')
    if state not in avail_states:
        raise ValueError('Invarid query: available state are ({0})'.format(u', '.join(avail_states)))
    data = {'status': state}
    cfg = config.parseconfig()
    _request('put', ISSUE.format(issueid=number, **cfg), data=data)


def commentto(number, params={}):
    template = """# comment below here\n"""
    val = util.inputwitheditor(template)
    data = {'content': util.rmcomment(val)}
    cfg = config.parseconfig()
    _request('post', ISSUE_COMMENTS.format(issueid=number, **cfg), data=data)


def _toticket(issue):
    cfg = config.parseconfig()
    j = dict(number = issue.key,
             state = issue.fields.status.name,
             title = issue.fields.summary,
             body = issue.fields.description,
             labels = issue.fields.issuetype.name,
             priority = issue.fields.priority,
             #milestone = nested_access(d, 'metadata.milestone'),
             creator = issue.fields.reporter.name,
             creator_fullname = issue.fields.reporter.displayName,
             html_url = issue.self,
             assignee = issue.fields.assignee.name,
             #comments = issue.fields.comment.total,
             created = _todatetime(issue.fields.created),
             updated = _todatetime(issue.fields.updated))
    return ticket.Ticket(**j)


def _issuedata_from_template(s):
    data = ticket.templatetodic(s, {'assignee':'responsible', 'labels':'kind', 'body':'content'})
    if 'title' not in data:
        raise ValueError('You must write a title')
    return data


# def _request(rtype, url, params={}, data=None, headers={}):
#     cfg = config.parseconfig()
#     r = None
#     # params['key'] = cfg['rtoken']
#     auth = (cfg['name'], cfg['rpassword'] or 'password')
#     if data:
#         r = getattr(requests, rtype)(url, data=data, params=params, headers=headers, auth=auth, verify=cfg['sslverify'])
#     else:
#         r = getattr(requests, rtype)(url, params=params, headers=headers, auth=auth, verify=cfg['sslverify'])
#     if not 200 <= r.status_code < 300:
#         raise requests.exceptions.HTTPError('[{0}] {1}'.format(r.status_code, r.url))
#     return r.json()

def _request(rtype, url, params={}, data=None):
    cfg = config.parseconfig()
    # session = requests
    # if cfg['btoken'] and cfg['btoken_secret']:
    #     service = OAuth1Service(name='bitbucket', consumer_key=CONSUMER_KEY, consumer_secret=CONSUMER_SECRET,
    #                         request_token_url=OAUTH_REQUEST,
    #                         access_token_url=OAUTH_ACCESS,
    #                         authorize_url=OAUTH_AUTH)
    #     session = service.get_auth_session(cfg['btoken'], cfg['btoken_secret'])
    session = requests
    r = None
    if data:
        r = getattr(session, rtype)(url, data=data, params=params, verify=cfg['sslverify'])
    else:
        r = getattr(session, rtype)(url, params=params)
    if not 200 <= r.status_code < 300:
        raise requests.exceptions.HTTPError('[{0}] {1}'.format(r.status_code, r.url))
    return r.json()

def _todatetime(dstr):
    if isinstance(dstr, basestring):
        return datetime.datetime.strptime(dstr.rpartition("-")[0], DATEFMT)
