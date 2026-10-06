import time
from contextlib import contextmanager

import httpx
import pytest

from scanner.config import Settings
from scanner.detectors import Detectors
from scanner.network import Budget, Network, Observation
from scanner.report import Redactor, Report, Results


def response(status, body=b'', headers=None):
    return httpx.Response(status, headers=headers or {}, stream=httpx.ByteStream(body))


def reference():
    return Observation('auth-1','http://127.0.0.1:3000/private','GET',200,httpx.Headers({'Content-Type':'application/json'}),b'{"account":"stable protected reference"}',False,True)


@contextmanager
def context(handler):
    settings=Settings('http://127.0.0.1:3000')
    report=Report()
    results=Results(report,Redactor())
    net=Network(settings,Budget(50,time.monotonic()+30),results,transport=httpx.MockTransport(handler))
    try:
        yield net,report,Detectors(net,results)
    finally:
        net.close()


@pytest.mark.parametrize('post_status,expected',[(403,'negative'),(405,'negative'),(500,'inconclusive'),(200,'inconclusive')])
def test_method_denial_is_not_confused_with_ambiguous_response(post_status,expected):
    def handler(request):
        return response(post_status if request.method=='POST' else 403,b'Unrelated response')
    with context(handler) as (net,report,detectors):
        detectors.method_tampering(reference(),net)
        assert report.checks['http_method_tampering'][expected]==1
        assert report.findings==[]
        assert report.checks['http_method_tampering']['details'][0]['reason']


def test_login_redirect_after_post_is_a_negative_control():
    def handler(request):
        if request.url.path=='/entry':
            return response(200,b'<form method="post"><input name="u"><input name="p" type="password"></form>',{'Content-Type':'text/html'})
        return response(302,headers={'Location':'/entry'})
    with context(handler) as (net,report,detectors):
        detectors.method_tampering(reference(),net)
        check=report.checks['http_method_tampering']
        assert check['negative']==1 and check['inconclusive']==0
        assert check['details'][0]['terminal_statuses']==[200,200]


def test_cookie_with_flags_is_counted_as_inspected():
    with context(lambda r: response(200,headers={'Set-Cookie':'sid=sensitive-session; Path=/; HttpOnly'})) as (net,report,detectors):
        net.request('GET',str(net.scope.base))
        detectors.cookie_flags(reference())
        check=report.checks['session_cookie_flags']
        assert check['tested']==check['negative']==1
        assert check['reasons']=={'applicable_cookie_flags_present':1}
        assert 'sensitive-session' not in report.model_dump_json()


def test_numeric_redirect_id_is_explicitly_not_tested():
    def forbidden(request):
        pytest.fail('No URL destination discovered: must not guess parameters')
    with context(forbidden) as (net,report,detectors):
        detectors.redirects(['http://127.0.0.1:3000/go?destination=1'])
        check=report.checks['open_redirect']
        assert check['tested']==0 and check['skipped']==1
        assert 'no_supported_destination_parameter' in check['reasons']


def test_relative_redirect_path_is_a_candidate_without_hardcoded_parameter_name():
    def handler(request):
        if request.url.path=='/forward':
            return response(302,headers={'Location':'article.html'})
        return response(200,b'public page')
    with context(handler) as (net,report,detectors):
        detectors.redirects(['http://127.0.0.1:3000/forward?unusual_field=article.html'])
        check=report.checks['open_redirect']
        assert check['tested']==1 and check['inconclusive']==1
        assert check['reasons']=={'public_redirector_intent_unknown':1}
        assert report.findings==[]


def test_redirect_deduplicates_destinations_but_preserves_distinct_flows():
    def handler(request):
        if 'sid=authenticated' not in request.headers.get('cookie', ''):
            return response(403)
        destination = request.url.params.get('next') or request.url.params.get('return')
        return response(302, headers={'Location': destination})
    with context(handler) as (net, report, detectors):
        net.client.cookies.set('sid', 'authenticated', domain='127.0.0.1', path='/')
        detectors.redirects([
            'http://127.0.0.1:3000/go?next=/one',
            'http://127.0.0.1:3000/go?next=/two',
            'http://127.0.0.1:3000/other?next=/one',
            'http://127.0.0.1:3000/go?return=/one',
            'http://127.0.0.1:3000/go?next=/one&account=alpha',
            'http://127.0.0.1:3000/go?next=/two&account=beta',
        ])
        assert len(report.findings) == 5
        assert report.checks['open_redirect']['confirmed'] == 5
        assert report.checks['open_redirect']['tested'] == 6
        assert all(f.evidence['external_location_controlled'] for f in report.findings)
        assert all(len(f.evidence['probe_requests']) == 2 for f in report.findings)


@pytest.mark.parametrize('case,expected', [
    ('repeated_bypass', 1), ('one_success_only', 0),
    ('public_get', 0), ('different_body', 0), ('different_type', 0),
])
def test_method_tampering_requires_repeated_exact_bypass_and_denied_control(case, expected):
    auth = reference()
    posts = []
    def handler(request):
        if request.method == 'GET':
            return response(200 if case == 'public_get' else 403, auth.body,
                            {'Content-Type': 'application/json'})
        posts.append(request)
        status = 403 if case == 'one_success_only' and len(posts) == 2 else 200
        body = b'{"account":"another account, unrelated response"}' if case == 'different_body' else auth.body
        content_type = 'text/plain' if case == 'different_type' else 'application/json'
        return response(status, body, {'Content-Type': content_type})
    with context(handler) as (net, report, detectors):
        detectors.method_tampering(auth, net)
        assert len(report.findings) == expected
        if expected:
            assert report.findings[0].method == 'POST'
            assert len(report.findings[0].evidence['anonymous_post']) == 2


@pytest.mark.parametrize('body,ctype,expected', [
    (b'{"people":[{"customer_cpf":"529.982.247-25"}]}', 'application/json', 1),
    (b'<input name="cpf" value="529.982.247-25">', 'text/html', 1),
    (b'{"cpf":"***.***.***-**"}', 'application/json', 0),
    (b'{"cpf":"529.982.247-24"}', 'application/json', 0),
    (b'{"order_id":"52998224725"}', 'application/json', 0),
    (b'CPF ficticio: 529.982.247-25', 'text/plain', 0),
])
def test_cpf_required_cases_and_no_raw_identifiers_in_report(body, ctype, expected):
    with context(lambda r: response(200)) as (net, report, detectors):
        obs = Observation('cpf-1', reference().url, 'GET', 200,
                          httpx.Headers({'Content-Type': ctype}), body, False, False)
        detectors.cpf(obs)
        assert len(report.findings) == expected
        saved = report.model_dump_json()
        assert '529.982.247-25' not in saved and '52998224725' not in saved


def test_cpf_unexamined_json_is_inconclusive_not_negative():
    import json
    body = json.dumps([{}] * 200 + [{'cpf': '529.982.247-25'}]).encode()
    with context(lambda r: response(200)) as (net, report, detectors):
        obs = Observation('cpf-limit', reference().url, 'GET', 200,
                          httpx.Headers({'Content-Type': 'application/json'}), body, False, False)
        detectors.cpf(obs)
        assert report.findings == []
        assert report.checks['cpf_exposure']['inconclusive'] == 1
        assert report.checks['cpf_exposure']['negative'] == 0
        assert report.checks['cpf_exposure']['reasons'] == {'json_traversal_limit': 1}


