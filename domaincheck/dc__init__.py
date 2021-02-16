import logging
import azure.functions as func
import json
from . import domain_checker as dc


def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function is processing a request.')
    
    # get the request
    url = req.params.get('url')
    # url = ''
    print(type(req))
    print(req.params)
    
    # print(dc.check_domain_punycode(url))
    
    # send the response
    logging.info(req.method)
    if url:
        return func.HttpResponse(
            json.dumps(dc.req_vt_whois_maldom_puny(url)),
            # json.dumps(dc.check_domain_punycode(url)),
            status_code=200
        )
    else:
        return func.HttpResponse(
            "insert a url parameter for a result :D",
            status_code=200
        )
    logging.info('Python HTTP trigger function finish processing a request.')