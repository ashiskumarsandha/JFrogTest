from datetime import datetime, timedelta, timezone
from locust import HttpUser, wait_time, between, task, SequentialTaskSet
import csv
import time
import docker
import os


class RepoAPIs(SequentialTaskSet):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.violation_log_file = None
        self.scan_log_file = None
        self.uniq_idn = None
        self.docker_image = None
        self.repo_name = None
        self.docker_client = None
        self.iteration = None
        self.headers = None
        self.Password = None
        self.Username = None

    def on_start(self):
        script_dir = os.path.dirname(__file__)
        csv_path = os.path.join(script_dir, "Resources", "Credentials.csv")
        with open(csv_path, mode="r") as file:
            reader = csv.DictReader(file)
            creds = next(reader)
            self.Username = creds["Username"]
            self.Password = creds["Password"]
        self.headers = {"Content-Type": "application/json",
                        "Authorization": "Basic QXNoaXNKRnJvZ1VzZXI6QXNoaXNKRnJvZ1Bhc3N3b3JkQDEyMw=="}
        self.iteration = 0
        self.docker_client = docker.from_env()
        self.docker_login()
        self.uniq_idn = self.generate_uniqueidentifier()
        self.scan_log_file = "/mnt/locust/Results/scan_status_times.csv"
        self.violation_log_file = "/mnt/locust/Results/violation_status_times.csv"
        os.makedirs("Results", exist_ok=True)

        if not os.path.exists(self.scan_log_file):
            with open(self.scan_log_file, mode='w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(["repo_name", "start_time_utc", "end_time_utc", "elapsed_seconds"])

        if not os.path.exists(self.violation_log_file):
            with open(self.violation_log_file, mode='w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(["repo_name", "start_time_utc", "end_time_utc", "elapsed_seconds"])

    def docker_login(self):
        self.docker_client.login(
            username=self.Username,
            password=self.Password,
            registry="trials6p3nw.jfrog.io",
        )

    @staticmethod
    def generate_uniqueidentifier():
        return int(time.time() * 1000)

    @task
    def create_repo(self):
        self.repo_name = f"docker-repo-{self.uniq_idn}"
        response = self.client.put(f"artifactory/api/repositories/{self.repo_name}",
                                   headers=self.headers,
                                   json={
                                       "key": self.repo_name,
                                       "projectKey": "",
                                       "packageType": "docker",
                                       "rclass": "local",
                                       "xrayIndex": True
                                   },
                                   name="R01_CreateRepo")
        expected_response = f"Successfully created repository '{self.repo_name}' "
        if response.status_code == 200:
            assert expected_response in response.text, (
                f"Repo Creation Failed with name {self.repo_name}"
            )

    @task
    def verify_repo_exists(self):
        response = self.client.get(f"artifactory/api/repositories",
                                   headers=self.headers,
                                   name="R02_VerifyRepo")

        if response.status_code == 200:
            assert self.repo_name in [repo["key"] for repo in response.json()], (
                f"Repo '{self.repo_name}' not found in repositories list"
            )

    @task
    def tag_push_dockerimage(self):
        if self.iteration%50 == 0:
            self.docker_login()

        self.image_name = f"jfdimg-{self.uniq_idn}"
        self.tag_name = f"V1.0-{self.uniq_idn}"
        try:
            self.docker_image = self.docker_client.images.get("alpine:3.9")
        except docker.errors.ImageNotFound:
            print("alpine:3.9 not found locally. Pulling from Docker Hub...")
            self.docker_image = self.docker_client.images.pull("alpine:3.9")

        self.docker_image.tag(f"trials6p3nw.jfrog.io/{self.repo_name}/{self.image_name}", tag=self.tag_name)
        self.docker_client.images.push(f"trials6p3nw.jfrog.io/{self.repo_name}/{self.image_name}")

    @task
    def create_security_policy(self):
        self.security_policy_name = f"sec-policy-{self.uniq_idn}"
        rule_name = f"sec-policy-{self.uniq_idn}-rule"

        response = self.client.post("xray/api/v2/policies",
                                    headers=self.headers,
                                    json={
                                        "name": self.security_policy_name,
                                        "description": "This is a specific CVEs security policy",
                                        "type": "security",
                                        "rules": [
                                            {
                                                "name": rule_name,
                                                "criteria": {
                                                    "malicious_package": False,
                                                    "fix_version_dependant": False,
                                                    "min_severity": "high"
                                                },
                                                "actions": {
                                                    "mails": [],
                                                    "webhooks": [],
                                                    "fail_build": False,
                                                    "block_release_bundle_distribution": False,
                                                    "block_release_bundle_promotion": False,
                                                    "notify_deployer": False,
                                                    "notify_watch_recipients": False,
                                                    "create_ticket_enabled": False,
                                                    "block_download": {
                                                        "active": False,
                                                        "unscanned": False
                                                    }
                                                },
                                                "priority": 1
                                            }
                                        ]
                                    },
                                    name="R04_CreateSecurityPolicy")
        expected_response = "Policy created successfully"
        json_response = response.json()
        if response.status_code == 201:
            assert expected_response == json_response.get("info"), (
                f"Security Policy failed for {self.security_policy_name}"
            )

    @task
    def create_watch(self):
        self.watch_name = f"watch-{self.uniq_idn}"
        response = self.client.post("xray/api/v2/watches",
                                    headers=self.headers,
                                    json={
                                            "general_data": {
                                                "name": self.watch_name,
                                                "description": "This is an example watch #1",
                                                "active": True
                                            },
                                            "project_resources": {
                                                "resources": [
                                                    {
                                                        "type": "repository",
                                                        "bin_mgr_id": "default",
                                                        "name": "docker-trial",
                                                        "filters": [
                                                            {
                                                                "type": "regex",
                                                                "value": ".*"
                                                            }
                                                        ]
                                                    }
                                                ]
                                            },
                                            "assigned_policies": [
                                                {
                                                    "name": self.security_policy_name,
                                                    "type": "security"
                                                }
                                            ]
                                        },
                                    name="R05_CreateWatch")
        expected_response = "Watch has been successfully created"
        json_response = response.json()
        if response.status_code == 201:
            assert expected_response == json_response.get("info"), (
                f"Watch creation failed for {self.watch_name}"
            )

    @task
    def apply_watch(self):
        response = self.client.post("xray/api/v1/applyWatch",
                                    headers=self.headers,
                                    json={
                                        "watch_names": [
                                            self.watch_name
                                        ],
                                        "date_range":
                                            {
                                                "start_date": "2025-04-07T10:25:00+02:00",
                                                "end_date": "2025-04-07T10:30:00+02:00"
                                            }
                                    },
                                    name="R06_ApplyWatch")
        expected_response = "History Scan is in progress"
        json_response = response.json()
        if response.status_code == 202:
            assert expected_response == json_response.get("info"), (
                f"History scan failed for {self.watch_name}"
            )

    @task
    def check_scan_status(self):
        max_time = 120
        poll_interval = 5
        elapsed_time = 0
        start_time = datetime.now(timezone.utc)

        while elapsed_time < max_time:
            response = self.client.post("xray/api/v1/artifact/status",
                                        headers=self.headers,
                                        json={
                                            "repo" : self.repo_name,
                                            "path" : self.image_name+"/"+self.tag_name+"/"+"manifest.json"
                                        },
                                        name="R07_CheckScanStatus")
            if response.status_code == 200:
                json_response = response.json()
                curr_status = json_response.get("overall", {}).get("status", "").upper()
                if curr_status == "DONE":
                    end_time = datetime.now(timezone.utc)
                    elapsed = (end_time - start_time).total_seconds()

                    with open(self.scan_log_file, mode='a', newline='') as file:
                        writer = csv.writer(file)
                        writer.writerow([
                            self.repo_name,
                            start_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                            end_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                            elapsed
                        ])
                    break
                else:
                    time.sleep(poll_interval)
                    elapsed_time += poll_interval
            else:
                print("Check scan status failed with response code : "+ str(response.status_code) + ", for Repo : "+ self.repo_name)
        else:
            print("Overall Status did not become DONE within "+str(max_time) + " seconds" + ", for Repo : "+ self.repo_name)

    @task
    def verify_violation(self):
        max_time = 120
        poll_interval = 5
        elapsed_time = 0
        start_time = datetime.now(timezone.utc)

        while elapsed_time < max_time:
            response = self.client.post("xray/api/v1/violations",
                                        headers=self.headers,
                                        json={
                                            "filters": {
                                                "watch_name": "Security_watch_1",
                                                "violation_type": "Security",
                                                "min_severity": "High",
                                                "resources": {
                                                    "artifacts": [
                                                        {
                                                            "repo": self.repo_name,
                                                            "path": self.image_name + "/" + self.tag_name + "/" + "manifest.json"
                                                        }
                                                    ]
                                                }
                                            },
                                            "pagination": {
                                                "order_by": "created",
                                                "direction": "asc",
                                                "limit": 100,
                                                "offset": 1
                                            }
                                        },
                                        name="R08_VerifyViolation")

            if response.status_code == 200:
                json_response = response.json()
                violation_count = json_response.get("total_violations")
                if violation_count > 0:
                    end_time = datetime.now(timezone.utc)
                    elapsed = (end_time - start_time).total_seconds()

                    with open(self.violation_log_file, mode='a', newline='') as file:
                        writer = csv.writer(file)
                        writer.writerow([
                            self.repo_name,
                            start_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                            end_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                            elapsed
                        ])
                    break
                else:
                    time.sleep(poll_interval)
                    elapsed_time += poll_interval
            else:
                print("Violation check failed with Response Code : " + str(response.status_code)  + ", for Repo : "+ self.repo_name)
        else:
            print("Violation Count did not become > 0 within " + str(max_time) + " seconds" + ", for Repo : "+ self.repo_name)


    @task
    def finish(self):
        self.interrupt()

class RepoScenario(HttpUser):
    tasks = [RepoAPIs]
    wait_time = between(5,20)