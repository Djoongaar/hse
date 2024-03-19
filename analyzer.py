#!/usr/bin/env python3

# (c) [2024] Evgeny S.
# All rights reserved.
# Any part of this script can be reproduced, distributed freely
# or by means, electronic, mechanical, photocopying, recording or other means,
# without the prior written permission of the copyright owner.

import json
import os
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
        self.__file_path = "invoice-42369643.html"
        self.__upload_file_url = "https://www.virustotal.com/api/v3/files"
        self.__headers = {"accept": "application/json", "x-apikey": self.__api_key}
        self.__file_id = self.__upload()
        self.__analysis_url = "https://www.virustotal.com/api/v3/analyses/{}".format(self.__file_id)
        self.__behaviours_url = "https://www.virustotal.com/api/v3/files/{}/behaviour_summary".format(
            self.__get_sha256())
        self.__report_data = self.__analyze()
        self.__report_df = pd.concat(
            [
                self.__get_malware_report(),
                self.__get_tags_report(),
                self.__get_hosts_report()
            ],
            axis=0)

    def __upload(self):
        """
        Upload file into VirusTotal server
        :return:
        """
        with open(self.__file_path, "rb") as file:
            files = {"file": (self.__file_path, file)}
            response = requests.post(self.__upload_file_url, headers=self.__headers, files=files)
        return response.json()["data"]["id"]

    def __get_sha256(self):
        response = requests.get(self.__analysis_url, headers=self.__headers)
        return response.json()["meta"]["file_info"]["sha256"]

    def __analyze(self):
        """
        Analyze file with VirusTotalApi
        :return: JSON response
        """
        response = requests.get(self.__analysis_url, headers=self.__headers)
        return response.json()

    def __get_behavior_data(self):
        return requests.get(self.__behaviours_url, headers=self.__headers)

    def __get_tags_report(self):
        behavior_data = self.__get_behavior_data()
        tags = behavior_data.json()["data"]["tags"]
        return pd.DataFrame(tags, columns=["tags"])

    def __get_hosts_report(self):
        behavior_data = self.__get_behavior_data()
        dns_lookups = behavior_data.json()["data"]["dns_lookups"]
        hosts = []
        for lookup in dns_lookups:
            hostname = lookup["hostname"]
            hosts.append(hostname)
            resolved_ips = lookup.get("resolved_ips", [])
            for resolved_ip in resolved_ips:
                hosts.append(resolved_ip)
        hosts_df = pd.DataFrame(hosts, columns=["hostname"])

        return hosts_df

    def __get_malware_report(self):
        """
        Create dataframe from JSON data
        :return: pandas dataframe
        """
        data_arr = []
        report = self.__report_data["data"]["attributes"]["results"]
        if report:
            with open("report.json", "w") as file:
                json.dump(report, file, indent=4)

        # Немного отошел от формального выполнения ДЗ
        # составил отчет в виде таблицы детектирования угроз
        # где True если угроза детектировала, а иначе False
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


class VulnersAnalyzer:
    def __init__(self):
        self.__url = 'https://vulners.com/api/v3/burp/softwareapi/'
        self.__api_key = "QY6X9YK1FO1R42RU3RJ7H050X8SJ4OLPMNBUVOXPKQWXYPTIQFYOIP7U9RTI1GY3"
        self.__headers = {"Content-type": "application/json"}
        self.__report_json = self.__create_report_json()
        self.__report_df = self.__get_report_df()
        self.__to_stdout()
        self.__to_csv()

    def __create_report_json(self):
        file_path = "vulners_report.json"
        with open("software.json", "r") as file:
            data = json.load(file)
        report_json = {"report": []}
        for software in data:
            software_data = {
                "software": software["Program"],
                "version": software["Version"],
                "type": "software",
                "maxVulnerabilities": 100,
                "apiKey": self.__api_key
            }
            response_json = requests.post(self.__url, headers=self.__headers, json=software_data)
            response_dict = json.loads(response_json.text)
            response_dict["software"] = software["Program"]
            response_dict["version"] = software["Version"]
            report_json["report"].append(response_dict)
        with open(file_path, "w") as vulners_report:
            json.dump(report_json, vulners_report, indent=4)

            return file_path

    def __get_report_df(self):
        with open(self.__report_json, "r") as vulners_report:
            data = json.load(vulners_report)

        cve = []

        for result in data["report"]:
            data = result["data"]
            if data.get("search"):
                values = data.get("search")
                for value in values:
                    cve.append([
                        result["software"],
                        result["version"],
                        True,
                        value["_source"]["cvelist"],
                        value["_source"]["href"],
                        value["_source"]["description"]
                    ])
            else:
                cve.append([
                    result["software"],
                    result["version"],
                    False,
                    None,
                    None,
                    None
                ])
        return pd.DataFrame(cve, columns=["software", "version", "is_detected", "cve_list", "href", "description"])

    def __to_csv(self):
        return self.__report_df.to_csv("vulners.csv", index=False, sep=";", encoding="utf-8")

    def __to_stdout(self):
        print(self.__report_df)


if __name__ == "__main__":
    Unzipper()
    df = VirusTotalAnalyzer()
    df.to_stdout()
    df.to_csv()
    VulnersAnalyzer()
