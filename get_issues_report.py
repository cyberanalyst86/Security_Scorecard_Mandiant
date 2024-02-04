import requests
import pandas as pd
import yaml
from yaml import SafeLoader
import time
import datetime
import io
import re
import numpy as np
from get_industry_factor_score import get_industry_score_grade
from get_industry_factor_score import get_industry_factor_score
from get_industry_factor_score import industry_merge_df
from get_company_factor_score import get_company_score_grade
from get_company_factor_score import get_company_factor_score
from get_company_factor_score import company_merge_df
from get_mandiant_cve_context import get_mandiant_cve_context

def get_today_date():

    now = datetime.datetime.now()
    today_date = now.strftime("%d-%m-%Y")

    return today_date

def configure_api_headers(apitoken):

    headers = {
        'Accept': 'application/json; charset=utf-8',
        'Content-Type': 'application/json',
        'Authorization': 'Token ' + apitoken,
        'cache-control': 'no-cache',
    }

    return headers

def get_apitoken():

    with open(
            "api_cred.yaml") as f:
        conf = yaml.load(f, Loader=SafeLoader)

    apitoken = conf['ssc_api']['api_token']
    return apitoken

def add_date_of_enquiry(df, dt_string):
    date_of_enquiry_list = []

    issue_list = df["ISSUE ID"].values.tolist()

    for i in range(len(issue_list)):
        date_of_enquiry_list.append(dt_string)

    df["DATE OF ENQUIRY"] = date_of_enquiry_list

    column_to_move = 'DATE OF ENQUIRY'

    moved_column = df.pop(column_to_move)

    df.insert(0, column_to_move, moved_column)

    return df


def add_findings_url(df, company):


    url_header = "https://platform.securityscorecard.io/#/scorecard/" + str(company) + "/issues/"

    findings_url_list = []

    for index, row in df.iterrows():
        factor_name = row["FACTOR NAME"].replace(" ", "_")

        findings_url = url_header + str(factor_name) + "/" + str(row["ISSUE TYPE CODE"]) + "/"

        findings_url_list.append(findings_url)

    df["FINDINGS URL"] = findings_url_list

    column_to_move = 'FINDINGS URL'

    moved_column = df.pop(column_to_move)

    df.insert(0, column_to_move, moved_column)

    return df


def get_generated_report(report_url, headers):
    response = requests.get(report_url, headers=headers)

    if response.status_code == 200:

        file_like_object = io.BytesIO(response.content)

        print("get generated report successfully!!!")
        # Read CSV content from the file-like object into a Pandas DataFrame
        df = pd.read_csv(file_like_object)

    else:

        print("Failed to get generated report. Status code:", response.status_code)

    return df

#def get_generated_report_url(headers):
def get_generated_report_url(report_id, headers):
    url = "https://api.securityscorecard.io/reports/recent"

    response = requests.get(url, headers=headers)

    df = pd.DataFrame.from_dict(response.json())

    for index, row in df.iterrows():

        if row["entries"]["id"] == report_id:

            download_url = row["entries"]["download_url"]

        else:

            continue

    return download_url


def generate_report(headers, company):
    url = "https://api.securityscorecard.io/reports/issues"
    payload = {
        "scorecard_identifier": company,
        "format": "csv"
    }

    response = requests.post(url, json=payload, headers=headers)

    print(response.text)

    # -------------------------Regex for report id-------------------------#

    pattern = r'"id"\s*:\s*"([^"]+)"'

    match_report_id = re.search(pattern, response.text)

    if match_report_id:

        report_id = match_report_id.group(1)

    else:

        print("error")

    return report_id


def main():

    # ---------------------------------Initialisation---------------------------------#

    apitoken = get_apitoken()
    headers = configure_api_headers(apitoken)
    today_date = get_today_date()

    # ---------------------------------Get User Input---------------------------------#

    industry = input("Enter industry: ")
    company_name = input("Enter company name:")
    company_domain = input("Enter company domain: ")


    # ---------------------------------Generate Report---------------------------------#

    report_id = generate_report(headers, company_domain)

    time.sleep(10)

    report_url = get_generated_report_url(report_id, headers)

    # ---------------------------------Get Generated Report---------------------------------#

    df = get_generated_report(report_url, headers)

    # ---------------------------------Add Findings Url to DataFrame---------------------------------#

    df_add_findings_url = add_findings_url(df, company_domain)

    # ---------------------------------Add Date of Enquiry to DataFrame---------------------------------#

    df_report = add_date_of_enquiry(df_add_findings_url, today_date)

    # ---------------------------------Add Company Score Grade to DataFrame---------------------------------#

    score, grade = get_company_score_grade(headers, company_domain)

    df_company_factor_score = get_company_factor_score(headers, company_domain)

    df_company_merge = company_merge_df(df_company_factor_score, df_report, score, grade)

    # ---------------------------------Add Industry Score Grade to Dataframe---------------------------------#
    industry , score, grade = get_industry_score_grade(headers, industry)
    df_industry_factor_score = get_industry_factor_score(headers, industry)
    df_industry_merge = industry_merge_df(df_industry_factor_score, df_company_merge, industry, score, grade)

    # ---------------------------------Get Mandiant CVE Context---------------------------------#

    cve_list = df_industry_merge["CVE"].replace(np.nan, "No CVE").tolist()

    df_cve_context = get_mandiant_cve_context(cve_list,df_industry_merge)

    company_name_list = []

    for i in range(len(df_cve_context.index)):

        company_name_list.append(company_name)

    df_cve_context["Company Name"] = company_name_list

    # ---------------------------------Output to Excel---------------------------------#

    df_cve_context.to_excel(str(today_date) + "_" + str(company_name) + "_ssc.xlsx", index=False)

    print("SSC report exported!!!")

if __name__ == "__main__":
    main()