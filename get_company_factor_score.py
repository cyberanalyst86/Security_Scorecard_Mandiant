import requests
import re
import pandas as pd

def capitalize_first_letters(input_string):
    # Split the string by spaces
    words = input_string.split()

    # Capitalize the first letter of each word
    capitalized_words = [word.capitalize() for word in words]

    # Join the words back together
    result = ' '.join(capitalized_words)

    return result

def company_merge_df(df_score_grade, df_issues, score, grade):

    merged_df = pd.merge(df_score_grade, df_issues, on='FACTOR NAME',
                         how='right')  # 'inner' join, change 'how' as needed

    score_list = []
    grade_list = []

    for i in range(len(merged_df)):
        score_list.append(score)
        grade_list.append(grade)

    merged_df["COMPANY SCORE"] = score_list
    merged_df["COMPANY GRADE"] = grade_list

    return merged_df


def get_company_score_grade(headers, company):

    url = "https://api.securityscorecard.io/companies/" + str(company)

    response = requests.get(url, headers=headers)

    match_score = re.search(r'"score":(\d+)', response.text)
    match_grade = re.search(r'"grade":"([A-Za-z])"', response.text)

    if match_score and match_grade:

        score = match_score.group(1)
        grade = match_grade.group(1)

    else:

        print("error")

    return score, grade

def get_company_factor_score(headers, company):

    url = "https://api.securityscorecard.io/companies/" + str(company) + "/factors"

    response = requests.get(url, headers=headers)

    df = pd.DataFrame.from_dict(response.json())

    factor_list = []
    score_list = []

    for index, row in df.iterrows():

        factor_list.append(row["entries"]["name"])
        score_list.append(row["entries"]["score"])

    score_data = {
        'FACTOR NAME': factor_list,
        'COMPANY FACTOR SCORE': score_list,
    }

    df = pd.DataFrame(score_data)

    deduplicated_df = df.drop_duplicates()

    for index, row in deduplicated_df.iterrows():

        factor_name_string = capitalize_first_letters(row["FACTOR NAME"].replace("_", " "))
        deduplicated_df.loc[index, 'FACTOR NAME'] = factor_name_string

    return deduplicated_df
