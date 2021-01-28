import logging
import azure.functions as func
import json

def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')
    
    # get the request
    url = req.params.get('url')
    # send the response
    if url:
        return func.HttpResponse(
            json.dumps(view_vt(url)),
            status_code=200
        )
    else:
        return func.HttpResponse(
            "insert a url parameter for a result :D",
            status_code=200
        )

def view_vt(url):
    import os
    # pip install virustotal3(Unofficial).
    import virustotal3.core
    # url = "www.google.com"
    api_key = '***REMOVED***'

    # Data is returned as a dict. We can just iterate through to get the required information.
    analysis_result = virustotal3.core.URL(api_key).get_network_location(url)
    x = analysis_result['data']['attributes']['last_analysis_stats']
    return x
    #print('Analysis result: {} malicious, {} harmless, {} sus, {} timeout, {} undetected'.format(x['malicious'], x['harmless'], x['suspicious'], x['timeout'], x['undetected']))
