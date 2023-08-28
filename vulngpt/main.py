import os
import json
import openai
import requests


openai.api_key = os.environ["OPENAI_API_KEY"]

def ask_vuln(description, softwares):
    with open('prompt_long.txt', 'r') as file:
        prompt_tmpl = file.read()

    prompt = prompt_tmpl.format(description=description, softwares=softwares)

    analyze_vuln_info = {
        "name": "analyze_vuln_info",
        "description": "Analyze vulnerability information",
        "parameters": {
            "type": "object",
            "properties": {
                "categories": {
                    "type": "array",
                    "description": "Category e.g. OS, application, library, etc.",
                    "items": {
                        "type": "string",
                    }
                },
                "targets": {
                    "type": "array",
                    "description": "Targeted product names",
                    "items": {
                        "type": "string",
                    }
                }
            },
            "required": ["categories"],
        },
    }

    messages = [{"role": "user", "content": prompt}]
    functions = [analyze_vuln_info]

    response = openai.ChatCompletion.create(
        model="gpt-4-0613",
        # model="gpt-3.5-turbo-16k-0613",
        messages=messages,
        functions=functions,
        function_call="auto",  # auto is default, but we'll be explicit
    )

    response_message = response["choices"][0]["message"]

    result = {"job": {}, "token": {}}
    # result["prompt"] = prompt

    result["token"]["input"] = response["usage"]["prompt_tokens"]
    result["token"]["output"] = response["usage"]["completion_tokens"]
    result["token"]["total_price"] = calc_total_price(result["token"])

    if response_message.get("function_call"):
        args = json.loads(response_message["function_call"]["arguments"])
        result["job"]["categories"] = args["categories"]
        if args.get("targets"):
            result["job"]["targets"] = args["targets"]
        else:
            result["job"]["targets"] = []
        return result
    
    return None

def get_vuln_info(cveid):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cveid}"
    response = requests.get(url)
    vuln_info = response.json()

    cve = vuln_info["vulnerabilities"][0]["cve"]

    for desc in cve["descriptions"]:
        if desc["lang"] == "en":
            description = desc["value"]

    cpes = []
    if cve.get("configurations"):
        for config in cve["configurations"]:
            if config.get("nodes"):
                for node in config["nodes"]:
                    if node.get("cpeMatch"):
                        for cpeMatch in node["cpeMatch"]:
                            if cpeMatch["vulnerable"] == True:
                                cpes.append(cpeMatch["criteria"])
    
    softwares = []
    for cpe in cpes:
        arr = cpe.split(':')
        vendor = arr[3]
        product = arr[4]
        softwares.append(f"{vendor} {product}")
    softwares = list(set(softwares)) # emit duplication

    return {"description": description, "softwares": json.dumps(softwares)}

def calc_total_price(token): # gpt-4-* モデルを想定
    input_price = (0.03 * token["input"])/1000
    output_price = (0.06 * token["output"])/1000
    return input_price + output_price


if __name__ == "__main__":
    vuln_info = get_vuln_info("CVE-2022-0330")

    result = ask_vuln(vuln_info["description"], vuln_info["softwares"])
    print(result)