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

def industry_merge_df(df_score_grade, df_issues, industry, score, grade):

    merged_df = pd.merge(df_score_grade, df_issues, on='FACTOR NAME',
                         how='right')  # 'inner' join, change 'how' as needed

    industry_list = []
    score_list = []
    grade_list = []

    for i in range(len(merged_df)):
        industry_list.append(industry)
        score_list.append(score)
        grade_list.append(grade)

    merged_df["INDUSTRY"] = industry_list
    merged_df["INDUSTRY SCORE"] = score_list
    merged_df["INDUSTRY GRADE"] = grade_list

    column_to_move = 'COMPANY GRADE'

    moved_column = merged_df.pop(column_to_move)

    merged_df.insert(0, column_to_move, moved_column)

    column_to_move = 'COMPANY SCORE'

    moved_column = merged_df.pop(column_to_move)

    merged_df.insert(0, column_to_move, moved_column)


    column_to_move = "INDUSTRY GRADE"

    moved_column = merged_df.pop(column_to_move)

    merged_df.insert(0, column_to_move, moved_column)

    column_to_move = "INDUSTRY SCORE"

    moved_column = merged_df.pop(column_to_move)

    merged_df.insert(0, column_to_move, moved_column)

    column_to_move = "INDUSTRY"

    moved_column = merged_df.pop(column_to_move)

    merged_df.insert(0, column_to_move, moved_column)

    column_to_move = "DATE OF ENQUIRY"

    moved_column = merged_df.pop(column_to_move)

    merged_df.insert(0, column_to_move, moved_column)

    return merged_df

def get_industry_score_grade(headers, industry):

    url = "https://api.securityscorecard.io/industries/" + str(industry) + "/score"

    response = requests.get(url, headers=headers)

    print(response.text)

    match_industry = re.search(r'"industry":"([^"]+)"', response.text)
    match_score = re.search(r'"avg_score":(\d+)', response.text)
    match_grade = re.search(r'"avg_grade":"([A-Za-z])"', response.text)

    if match_industry and match_score and match_grade:

        industry = match_industry.group(1)
        score = match_score.group(1)
        grade = match_grade.group(1)

    else:

        print("error")

    return industry, score, grade

def get_industry_factor_score(headers, industry):

    url = "https://api.securityscorecard.io/industries/" + str(industry) + "/factors"

    response = requests.get(url, headers=headers)

    df = pd.DataFrame.from_dict(response.json())

    factor_list = []
    score_list = []

    for index, row in df.iterrows():

        factor_list.append(row["entries"]["name"])
        score_list.append(row["entries"]["score"])

    score_data = {
        'FACTOR NAME': factor_list,
        'INDUSTRY FACTOR SCORE': score_list,
    }

    df = pd.DataFrame(score_data)

    deduplicated_df = df.drop_duplicates()

    for index, row in deduplicated_df.iterrows():

        factor_name_string = capitalize_first_letters(row["FACTOR NAME"].replace("_", " "))
        deduplicated_df.loc[index, 'FACTOR NAME'] = factor_name_string

    return deduplicated_df

