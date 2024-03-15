#!/usr/bin/env python3

# (c) [2024] Evgeny S.
# All rights reserved.
# Any part of this script can be reproduced, distributed freely
# or by means, electronic, mechanical, photocopying, recording or other means,
# without the prior written permission of the copyright owner.


# Manual:
# Case #1: ./analyzer "invoice-42369643.xlsm"                  # To obtain report in stdout
# Case #2: ./analyzer "invoice-42369643.xlsm" "report.csv"     # To obtain report in .csv file


import sys
import requests
import pandas as pd


class VirusTotalAnalyzer:
    def __init__(self, file_path):
        self.__file_path = file_path
        self.__api_key = "8855876211e9e685efb3f3362691ac517d358f47406b2bcf988ab88ef3c40ca5"
        self.__upload_file_url = "https://www.virustotal.com/api/v3/files"
        self.__headers = {"accept": "application/json", "x-apikey": self.__api_key}
        self.__file_id = self.__upload(self.__file_path)
        self.__analysis_url = "https://www.virustotal.com/api/v3/analyses/{}".format(self.__file_id)
        self.__report_data = self.__analyze()
        self.__report_df = self.__create_df()

    def __unzip(self, path):
        """ Unzip file """
        pass

    def __upload(self, path):
        """
        Upload file into VirusTotal server
        :param path:
        :return:
        """
        with open(path, "rb") as file:
            files = {"file": (path, file)}
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

        for soft, res in report.items():
            data_arr.append([
                bool(res["result"]),
                res["engine_name"],
                res["result"]
            ])

        return pd.DataFrame(data_arr, columns=["is_detected", "software", "malware"])

    def to_stdout(self):
        print(self.__report_df)

    def to_csv(self, report_path):
        return self.__report_df.to_csv(report_path, index=False, sep=";", encoding="utf-8")

    def to_html(self, report_path):
        """ Method in progress """
        pass


if __name__ == "__main__":
    report_data = VirusTotalAnalyzer(sys.argv[1])
    try:
        if sys.argv[2].endswith(".csv"):
            report_data.to_csv(sys.argv[2])
        elif sys.argv[2].endswith(".html"):
            report_data.to_html(sys.argv[2])
        else:
            # Send DF to stdout, if format file is not correct
            report_data.to_stdout()
    except IndexError:
        # Send DF to stdout, if filename is not given
        report_data.to_stdout()
