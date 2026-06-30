import requests


def check_hash_vt(file_hash, api_key):
    if not api_key or api_key == "YOUR_API_KEY":
        return {"status": "no_key", "message": "VirusTotal API key is missing."}

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }

    try:
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            return {
                "status": "success",
                "malicious": stats["malicious"],
                "suspicious": stats["suspicious"],
                "undetected": stats["undetected"],
                "harmless": stats["harmless"]
            }
        elif response.status_code == 404:
            return {"status": "not_found", "message": "File never seen by VirusTotal."}
        else:
            return {"status": "error", "message": f"API returned status code {response.status_code}"}

    except requests.exceptions.RequestException as e:
        return {"status": "error", "message": str(e)}