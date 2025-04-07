####################################################################################
## Copyright (c) 2025 Red7en, LLC                                                 ##
##                                                                                ## 
## Permission is hereby granted, free of charge, to any person obtaining a copy   ##
## of this software and associated documentation files (the "Software"), to deal  ##
## in the Software without restriction, including without limitation the rights   ##
## to use, copy, modify, merge, publish, distribute, sublicense, and/or sell      ##
## copies of the Software, and to permit persons to whom the Software is          ##
## furnished to do so, subject to the following conditions:                       ##
##                                                                                ##
## The above copyright notice and this permission notice shall be included in all ##
## copies or substantial portions of the Software.                                ##
##                                                                                ##
## THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR     ##   
## IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,       ##
## FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE    ##
## AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER         ##
## LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,  ##
## OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE  ##
## SOFTWARE.                                                                      ##
####################################################################################

import json
from org.parosproxy.paros.extension.history import ExtensionHistory
from java.io import File, FileOutputStream, OutputStreamWriter

# Path to the output file
output_file = "C:\\Users\\wardell\\Desktop\\Hacking\\BurpExtension\\ZAPReqResp.json"

# Get the extension history
extHist = control.getExtensionLoader().getExtension(ExtensionHistory.NAME)

if extHist is not None:
    i = 1

    # Create file and set UTF-8 encoding for writing
    file_stream = FileOutputStream(File(output_file))
    writer = OutputStreamWriter(file_stream, "UTF-8")

    try:
        hr = extHist.getHistoryReference(i)

        # Start JSON array
        writer.write("[\n")

        first_entry = True

        while hr is not None:
            http_message = hr.getHttpMessage()

            # Extract request and response strings
            request = http_message.getRequestHeader().toString() + http_message.getRequestBody().toString()
            response = http_message.getResponseHeader().toString() + http_message.getResponseBody().toString()

            # Format request as a JSON object
            request_entry = {
                "number": i,
                "type": "request",
                "content": request
            }
            response_entry = {
                "number": i,   
                "type": "response",
                "content": response
            }

            # Add comma if it's not the first entry
            if not first_entry:
                writer.write(",\n")
            first_entry = False

            # Write request and response as part of a valid JSON array
            writer.write(json.dumps(request_entry, ensure_ascii=False, indent=4))
            writer.write(",\n")
            writer.write(json.dumps(response_entry, ensure_ascii=False, indent=4))

            # Move to the next record
            i += 1
            hr = extHist.getHistoryReference(i)

        # End JSON array
        writer.write("\n]")

        print("Requests and responses written to " + output_file)

    finally:
        # Close the writer properly
        writer.close()
        file_stream.close()

else:
    print("ExtensionHistory is not available.")

