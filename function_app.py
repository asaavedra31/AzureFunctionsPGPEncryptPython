import logging
import azure.functions as func
import pgpy
from azure.storage.blob import BlobServiceClient
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
import os

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

@app.function_name(name="HttpExample")
@app.route(route="HttpExample")
def HttpExample(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    name = req.params.get('name')
    if not name:
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            name = req_body.get('name')

    if name:
        return func.HttpResponse(f"Hello, {name}. This HTTP triggered function executed successfully.")
    else:
        return func.HttpResponse(
             "This HTTP triggered function executed successfully. Pass a name in the query string or in the request body for a personalized response.",
             status_code=200
        )

@app.function_name(name="PGPOperations")    
@app.route(route="PGPOperations", methods=["POST"])
def PGPOperations(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')
    try:
        mode = req.params.get('mode')  # 'encrypt' o 'decrypt'
        blob_path = req.params.get('blob_path')
        output_path = req.params.get('output_path')

        if mode == 'encrypt':
            public_key_str = req.get_json().get('public_key')
            if not blob_path or not output_path or not public_key_str:
                return func.HttpResponse("Missing parameters for encryption", status_code=400)

            conn_str = os.environ['AzureWebJobsStorage']
            blob_service_client = BlobServiceClient.from_connection_string(conn_str)

            container, blob_name = blob_path.split('/', 1)
            blob_client = blob_service_client.get_blob_client(container=container, blob=blob_name)
            blob_data = blob_client.download_blob().readall().decode('utf-8')

            public_key, _ = pgpy.PGPKey.from_blob(public_key_str)
            message = pgpy.PGPMessage.new(blob_data)
            encrypted_message = public_key.encrypt(message)
            encrypted_bytes = str(encrypted_message).encode('utf-8')

            out_container, out_blob_name = output_path.split('/', 1)
            out_blob_client = blob_service_client.get_blob_client(container=out_container, blob=out_blob_name)
            out_blob_client.upload_blob(encrypted_bytes, overwrite=True)

            return func.HttpResponse("Encrypted and saved successfully", status_code=200)

        elif mode == 'decrypt':
            keyvault_name = req.params.get('keyvault_name')
            secret_name = req.params.get('secret_name')
            if not blob_path or not output_path or not keyvault_name or not secret_name:
                return func.HttpResponse("Missing parameters for decryption", status_code=400)

            credential = DefaultAzureCredential()
            kv_uri = f"https://{keyvault_name}.vault.azure.net"
            client = SecretClient(vault_url=kv_uri, credential=credential)
            secret = client.get_secret(secret_name)
            private_key_str = secret.value

            conn_str = os.environ['AzureWebJobsStorage']
            blob_service_client = BlobServiceClient.from_connection_string(conn_str)

            container, blob_name = blob_path.split('/', 1)
            blob_client = blob_service_client.get_blob_client(container=container, blob=blob_name)
            encrypted_data = blob_client.download_blob().readall().decode('utf-8')

            private_key, _ = pgpy.PGPKey.from_blob(private_key_str)
            if private_key.is_protected:
                return func.HttpResponse("Private key is protected with a passphrase, which is not supported in this function", status_code=400)

            message = pgpy.PGPMessage.from_blob(encrypted_data)
            decrypted = private_key.decrypt(message).message

            out_container, out_blob_name = output_path.split('/', 1)
            out_blob_client = blob_service_client.get_blob_client(container=out_container, blob=out_blob_name)
            out_blob_client.upload_blob(decrypted.encode('utf-8'), overwrite=True)

            return func.HttpResponse("Decrypted and saved successfully", status_code=200)

        else:
            return func.HttpResponse("Invalid mode. Use 'encrypt' or 'decrypt'", status_code=400)

    except Exception as e:
        logging.exception("Encryption/Decryption failed.")
        return func.HttpResponse(f"Error: {str(e)}", status_code=500)

