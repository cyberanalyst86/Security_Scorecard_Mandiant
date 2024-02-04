import requests
import json
import yaml
from yaml.loader import SafeLoader
from requests.auth import HTTPBasicAuth
import pandas as pd
import yaml
from yaml import SafeLoader

def get_api_key():

    with open(
            "api_cred.yaml") as f:
        conf = yaml.load(f, Loader=SafeLoader)

    APIv4_key = conf['mandiant_api']['APIv4_key']
    APIv4_secret = conf['mandiant_api']['APIv4_secret']

    return APIv4_key, APIv4_secret

def get_vulnerability_details(vulnerability_id, headers):

    print("get vulnerability details")

    url = "https://api.intelligence.mandiant.com/v4/vulnerability/" + str(vulnerability_id) + "?rating_types=analyst,unrated,predicted"

    resp = requests.get(url=url, headers=headers)

    try:
        available_mitigation = resp.json()["available_mitigation"]
        cisa_known_exploited = resp.json()["cisa_known_exploited"]
        common_vulnerability_scores = resp.json()["common_vulnerability_scores"]
        cwe = resp.json()["cwe"]
        cwe_details = resp.json()["cwe_details"]
        date_of_disclosure = resp.json()["date_of_disclosure"]
        days_to_patch = resp.json()["days_to_patch"]
        epss = resp.json()["epss"]
        exploitation_consequence = resp.json()["exploitation_consequence"]
        exploitation_vectors = resp.json()["exploitation_vectors"]
        exploits = resp.json()["exploits"]
        first_publish_date = resp.json()["first_publish_date"]
        publish_date = resp.json()["publish_date"]
        was_zero_day = resp.json()["was_zero_day"]
        workarounds = resp.json()["workarounds"]

    except KeyError:

        available_mitigation = "cve no match in mandiant"
        cisa_known_exploited = "cve no match in mandiant"
        common_vulnerability_scores = "cve no match in mandiant"
        cwe = "cve no match in mandiant"
        cwe_details = "cve no match in mandiant"
        date_of_disclosure = "cve no match in mandiant"
        days_to_patch = "cve no match in mandiant"
        epss = "cve no match in mandiant"
        exploitation_consequence = "cve no match in mandiant"
        exploitation_vectors = "cve no match in mandiant"
        exploits = "cve no match in mandiant"
        first_publish_date = "cve no match in mandiant"
        publish_date = "cve no match in mandiant"
        was_zero_day = "cve no match in mandiant"
        workarounds = "cve no match in mandiant"

    return  available_mitigation, cisa_known_exploited, common_vulnerability_scores, cwe, cwe_details, date_of_disclosure, days_to_patch, epss, exploitation_consequence, exploitation_vectors, exploits, first_publish_date, publish_date, was_zero_day, workarounds

def get_mandiant_cve_context(cve_list, df_report):


    APIv4_key,   APIv4_secret = get_api_key()

    # ----------------------------Get Mandiant API Token-----------------------------#

    API_URL = 'https://api.intelligence.fireeye.com/token'
    headers = {
        'grant_type': 'client_credentials'
    }
    r = requests.post(API_URL, auth=HTTPBasicAuth(APIv4_key, APIv4_secret), data=headers)
    data = r.json()
    auth_token = data.get('access_token')

    url = "https://api.intelligence.mandiant.com/v4/search"
    bearer_token = "insert bearer token"
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Accept": "application/json",
        "X-App-Name": "insert your app name",
        "Content-Type": "application/json"
    }

    id_list = []
    name_list = []
    type_list = []
    description_list = []
    risk_list = []
    exploitation_state_list = []
    vulnerability_domain = "https://advantage.mandiant.com/vulnerabilities/"

    available_mitigation_list = []
    cisa_known_exploited_list = []
    common_vulnerability_scores_list = []
    cwe_list = []
    cwe_details_list = []
    date_of_disclosure_list = []
    days_to_patch_list = []
    epss_list = []
    exploitation_consequence_list = []
    exploitation_vectors_list = []
    exploits_list = []
    first_publish_date_list = []
    publish_date_list = []
    was_zero_day_list = []
    workarounds_list = []

    for CVE in cve_list:

        print(CVE)

        if CVE == 'No CVE':

            id_list.append("")
            name_list.append("")
            type_list.append("")
            description_list.append("")
            risk_list.append("")
            exploitation_state_list.append("")
            available_mitigation_list.append("")
            cisa_known_exploited_list.append("")
            common_vulnerability_scores_list.append("")
            cwe_list.append("")
            cwe_details_list.append("")
            date_of_disclosure_list.append("")
            days_to_patch_list.append("")
            epss_list.append("")
            exploitation_consequence_list.append("")
            exploitation_vectors_list.append("")
            exploits_list.append("")
            first_publish_date_list.append("")
            publish_date_list.append("")
            was_zero_day_list.append("")
            workarounds_list.append("")

        else:

            search_term = CVE

            post_body = {
                "search": search_term,
                "type": "vulnerability",
                "limit": 1,
                "sort_by": [
                    "relevance"
                ],
                "sort_order": "desc",
                "next": ""
            }

            resp = requests.post(url=url, headers=headers, data=json.dumps(post_body))

            df = pd.DataFrame.from_dict(resp.json())

            for index, row in df.iterrows():

                if row["objects"]["name"] == search_term:

                    print("get cve context")

                    available_mitigation, cisa_known_exploited, common_vulnerability_scores, cwe, cwe_details, date_of_disclosure, days_to_patch, epss, exploitation_consequence, exploitation_vectors, exploits, first_publish_date, publish_date, was_zero_day, workarounds = get_vulnerability_details(row["objects"]["id"], headers)

                    id_list.append(str(vulnerability_domain) + row["objects"]["id"])
                    name_list.append(row["objects"]["name"])
                    type_list.append(row["objects"]["type"])
                    description_list.append(row["objects"]["description"])
                    risk_list.append(row["objects"]["risk_rating"])
                    exploitation_state_list.append(row["objects"]["exploitation_state"])

                    available_mitigation_list.append(available_mitigation)
                    cisa_known_exploited_list.append(cisa_known_exploited)
                    common_vulnerability_scores_list.append(common_vulnerability_scores)
                    cwe_list.append(cwe)
                    cwe_details_list.append(cwe_details)
                    date_of_disclosure_list.append(date_of_disclosure)
                    days_to_patch_list.append(days_to_patch)
                    epss_list.append(epss)
                    exploitation_consequence_list.append(exploitation_consequence)
                    exploitation_vectors_list.append(exploitation_vectors)
                    exploits_list.append(exploits)
                    first_publish_date_list.append(first_publish_date)
                    publish_date_list.append(publish_date)
                    was_zero_day_list.append(was_zero_day)
                    workarounds_list.append(workarounds)


                else:

                    id_list.append("cve no match in mandiant")
                    name_list.append("cve no match in mandiant")
                    type_list.append("cve no match in mandiant")
                    description_list.append("cve no match in mandiant")
                    risk_list.append("cve no match in mandiant")
                    exploitation_state_list.append("cve no match in mandiant")
                    available_mitigation_list.append("cve no match in mandiant")
                    cisa_known_exploited_list.append("cve no match in mandiant")
                    common_vulnerability_scores_list.append("cve no match in mandiant")
                    cwe_list.append("cve no match in mandiant")
                    cwe_details_list.append("cve no match in mandiant")
                    date_of_disclosure_list.append("cve no match in mandiant")
                    days_to_patch_list.append("cve no match in mandiant")
                    epss_list.append("cve no match in mandiant")
                    exploitation_consequence_list.append("cve no match in mandiant")
                    exploitation_vectors_list.append("cve no match in mandiant")
                    exploits_list.append("cve no match in mandiant")
                    first_publish_date_list.append("cve no match in mandiant")
                    publish_date_list.append("cve no match in mandiant")
                    was_zero_day_list.append("cve no match in mandiant")
                    workarounds_list.append("cve no match in mandiant")

    df_report["MANDIANT ID"] = id_list
    df_report["CVE ID"] = name_list
    df_report["CVE TYPE"] = type_list
    df_report["CVE DESCRIPTION"] = description_list
    df_report["CVE RISK"] = risk_list
    df_report["Exploitation State"] = exploitation_state_list
    df_report["available_mitigation"] = available_mitigation_list
    df_report["cisa_known_exploited"] = cisa_known_exploited_list
    df_report["common_vulnerability_scores"] = common_vulnerability_scores_list
    df_report["cwe"] = cwe_list
    df_report["cwe_details"] = cwe_details_list
    df_report["date_of_disclosure"] = date_of_disclosure_list
    df_report["days_to_patch"] = days_to_patch_list
    df_report["epss"] = epss_list
    df_report["exploitation_consequence"] = exploitation_consequence_list
    df_report["exploitation_vectors"] = exploitation_vectors_list
    df_report["exploits"] = exploits_list
    df_report["first_publish_date"] = first_publish_date_list
    df_report["publish_date"] = publish_date_list
    df_report["was_zero_day"] = was_zero_day_list
    df_report["workarounds"] = workarounds_list

    return df_report