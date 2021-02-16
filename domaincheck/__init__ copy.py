import logging
import azure.functions as func
import json

def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')
    
    # get the request
    url = req.params.get('url')
    # send the response
    return func.HttpResponse(
        json.dumps(view_vt(url)),
        status_code=200
    )

    # if not name:
    #     try:
    #         req_body = req.get_json()
    #     except ValueError:
    #         pass
    #     else:
    #         name = req_body.get('name')
    # bodyText = req.params.get('bodyText')

    # if name:
    #     if bodyText:
    #         if bodyText == "This is legit":
    #             return func.HttpResponse(f"Hello, {name}. This text is real!")
    #         else:
    #             return func.HttpResponse(f"Hello, {name}. This text may be fake, consider cross checking it with other sources.")
    #     else:
    #         return func.HttpResponse(f"Hello, {name}. Try to add a test parameter in your request for a personalised response.")
    # else:
    #     return func.HttpResponse(
    #          #"This HTTP triggered function executed successfully. Pass a name in the query string or in the request body for a personalized response.",
    #          #try to use request { test:'insert string here' } for a personalised response
    #          "HTTP Request triggered correctly, try to add a test parameter in your request for a personalised response.",
    #          status_code=200
    #     )

def view_vt(url):
    import os
    # pip install virustotal3(Unofficial).
    import virustotal3.core
    # url = "www.google.com"
    api_key = '***REMOVED***'

    # Data is returned as a dict. We can just iterate through to get the required information.
    analysis_result = virustotal3.core.URL(api_key).get_network_location(url)
    # try:
    #     for x in analysis_result:
    #         print(x)
    # except:
    #     print('screwed up')
    x = analysis_result['data']['attributes']['last_analysis_stats']
    return x
    #print('Analysis result: {} malicious, {} harmless, {} sus, {} timeout, {} undetected'.format(x['malicious'], x['harmless'], x['suspicious'], x['timeout'], x['undetected']))
