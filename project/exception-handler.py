from rest_framework.views import exception_handler


def custom_exception_handler(exception, context):
    response = exception_handler(exception, context)

    if response is not None:
        customized_response = {'errors': []}
        try:
            for key, value in response.data.items():
                if type(value) == list:
                    value = value[0]
                if key == "detail":
                    error = value
                else:
                    error = f" {key}: {value}"

                customized_response['errors'] = error
                break
        except AttributeError:
            customized_response['errors'] = str(response.data[0])

        response.data = customized_response

    return response
