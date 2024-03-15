#!/usr/bin/env python3
import json
import os
# (c) [2024] Evgeny S.
# All rights reserved.
# Any part of this script can be reproduced, distributed freely
# or by means, electronic, mechanical, photocopying, recording or other means,
# without the prior written permission of the copyright owner.


import zipfile
import requests
import pandas as pd


class Unzipper:
    def __init__(self):
        self.__password = 'netology'
        self.__zip_path = "protected_archive.zip"
        self.__unzip()

    def __unzip(self):
        """ Unzip file """
        if self.__zip_path.endswith(".zip"):
            directory_to_extract_to = os.path.dirname(os.path.abspath(self.__zip_path))
            with zipfile.ZipFile(self.__zip_path, 'r') as zip_ref:
                zip_ref.extractall(directory_to_extract_to, pwd=bytes(self.__password, 'utf-8'))


class VirusTotalAnalyzer:
    def __init__(self):
        self.__api_key = "8855876211e9e685efb3f3362691ac517d358f47406b2bcf988ab88ef3c40ca5"
        self.__file_path = "invoice-42369643.xlsm"
        self.__upload_file_url = "https://www.virustotal.com/api/v3/files"
        self.__headers = {"accept": "application/json", "x-apikey": self.__api_key}
        self.__file_id = self.__upload()
        self.__analysis_url = "https://www.virustotal.com/api/v3/analyses/{}".format(self.__file_id)
        self.__report_data = self.__analyze()
        self.__report_df = self.__create_df()

    def __upload(self):
        """
        Upload file into VirusTotal server
        :return:
        """
        with open(self.__file_path, "rb") as file:
            files = {"file": (self.__file_path, file)}
            response = requests.post(self.__upload_file_url, headers=self.__headers, files=files)

        return response.json()["data"]["id"]

    def __analyze(self):
        """
        Analyze file with VirusTotalApi
        :return: JSON response
        """

        response = requests.get(self.__analysis_url, headers=self.__headers)
        return response.json()

    def __create_df(self):
        """
        Create dataframe from JSON data
        :return: pandas dataframe
        """
        data_arr = []
        report = self.__report_data["data"]["attributes"]["results"]
        if report:
            with open("report.json", "w") as file:
                json.dump(report, file, indent=4)

        for soft, res in report.items():
            data_arr.append([
                bool(res["result"]),
                res["engine_name"],
                res["result"]
            ])

        return pd.DataFrame(data_arr, columns=["is_detected", "software", "malware"])

    def to_stdout(self):
        print(self.__report_df)

    def to_csv(self):
        return self.__report_df.to_csv("report.csv", index=False, sep=";", encoding="utf-8")


if __name__ == "__main__":
    Unzipper()
    df = VirusTotalAnalyzer()
    df.to_stdout()
    df.to_csv()
