import logging

import azure.functions as func


def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    name = req.params.get('name')
    if not name:
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            name = req_body.get('name')
    bodyText = req.params.get('bodyText')

    if name:
        if bodyText:
            if bodyText == "This is legit":
                return func.HttpResponse(f"Hello, {name}. This text is real!")
            else:
                return func.HttpResponse(f"Hello, {name}. This text may be fake, consider cross checking it with other sources.")
        else:
            return func.HttpResponse(f"Hello, {name}. Try to add a bodyText parameter in your request for a more personalised response.")
    else:
        return func.HttpResponse(
             #"This HTTP triggered function executed successfully. Pass a name in the query string or in the request body for a personalized response.",
             #try to use request { test:'insert string here' } for a personalised response
             "HTTP Request triggered correctly, try to add a name parameter in your request for a personalised response.",
             status_code=200
        )
