# This file is subject to the terms and conditions defined in the file
# 'LICENSE.txt', which is part of this source code package.

import httplib2
import json
import os
import yaml
import fnmatch
import sys
import argparse
import time
import datetime
import pandas as pd


def find_files(directory, pattern):
    """ Find the file details in the given directory """
    try:
        for root, dirs, files in os.walk(directory, followlinks=True):
            for basename in files:
                if fnmatch.fnmatch(basename, pattern):
                    filename = os.path.join(root, basename)
                    yield filename
    except Exception as e:
        sys.stderr.write(e.message)
        exit(1)


def get_files(template_path, resource_type, skip_customer_resources=False):
    """ This will return the metadata jsonfile """
    try:
        json_files = []
        for file_path in find_files(template_path, '*.json'):
            folder_list = list(file_path.split("/"))
            if not ('/customer/' in file_path.lower() and skip_customer_resources):
                folder_name = list(folder_list[-1].split('.'))
                file_name = folder_name[-2]
                if resource_type in ['template', 'script', 'policy']:
                    if '_ignore' not in file_path and not file_name.startswith('Blueprint_'):
                        if folder_list[-2] == file_name:
                            json_files.append(file_path)
                else:
                    if file_name.startswith('Blueprint_'):
                        folder_name = "Blueprint_%s" % folder_list[-2]
                        if folder_name == file_name:
                            json_files.append(file_path)
                        else:
                            json_file = open(file_path, 'r')
                            content = json.dumps(json_file.read()).encode('utf-8')
                            json_file.close()
                            content = json.loads(content)
                            blueprint_details = json.loads(content)
                            bp_name = "Blueprint_%s" % blueprint_details.get('name')
                            if bp_name == file_name:
                                json_files.append(file_path)
        return json_files
    except Exception as e:
        sys.stderr.write(e.message)
        exit(1)


def config_detail():
    """ Config file read """
    try:
        parser = argparse.ArgumentParser(
            description="Used for validate the templates and push to corestack"
                        " template collection.")

        parser.add_argument(
            'api_endpoint', help="Endpoint in which the Application Running.")

        parser.add_argument('username', help="Username to authenticate API.")

        parser.add_argument('password', help="Password to authenticate API.")

        parser.add_argument('resource_type', choices=['template', 'script', 'policy', 'blueprint'],
                            help="Resource type to load(template/script/policy/blueprint)")

        parser.add_argument('resources_path', help="Path of the Resources Repository")

        parser.add_argument('load_type', choices=['S', 's', 'A', 'a'], help="Load Type: 'S-Selected, A-All'")

        parser.add_argument(
            '-n', '--names', default='', help="Names of resources to Load. Need Only when type is 's'")

        parser.add_argument('-c', '--csv', default='', help="Name of the CSV file from which template should be loaded")

        parser.add_argument(
            '--update', default=False, action="store_true", help='Option to update if resource already exists.')

        parser.add_argument('-p', '--project', default='', help="Name of project to load resources.")

        parser.add_argument('-s', '--scope', default='default', choices=['default', 'global', 'tenant', 'private'],
                            help="Scope of the resources if want to change.")
        parser.add_argument('--skip-customer-resources', default="N", choices=['yes', 'no', 'y', 'n', 'Y', 'N'],
                            help="Use this option if you want to skip loading customer templates & blueprints."
                                 "Supported only for blueprint and its corresponding template loader.")

        args = parser.parse_args()

        if args.load_type in ['S', 's']:
            if not args.names:
                sys.stderr.write("Resource names mandatory when type is 'S'.\n")
                exit(1)
        if not os.path.exists(args.resources_path):
            sys.stderr.write("Resources_path is not exists.\n")
            exit(1)

        if not args.api_endpoint.endswith('/'):
            args.api_endpoint = "%s/" % args.api_endpoint

        return args.api_endpoint, args.username, args.password, \
               args.resource_type, args.resources_path, args.load_type, \
               args.names, args.update, args.project, args.scope, args.csv, args.skip_customer_resources
    except Exception as e:
        sys.stderr.write(e.message)
        exit(1)


def load_template_path_from_csv(csv_file_path, col_name=None):
    """
    will process a csv file and returns the list of items to be loaded
    :param csv_file_path: path of the csv
    :param col_name: resource type
    :return: list of items
    """
    try:
        data = pd.read_excel(csv_file_path)
        data[col_name].dropna(inplace=True)
        return data[col_name].tolist()
    except Exception as e:
        sys.stderr.write('Template Loading from csv Failed: %s\n' % e.message)
        exit(1)


def api_authenticate(username, password, api_url, project_name):
    """ Get the Auth token value """
    try:

        http_client = httplib2.Http()
        body = {'username': username, 'password': password}
        url = "%s%s" % (api_url, 'auth/tokens?auth_method=password')
        resp, content = http_client.request(
            url, method="POST", body=json.dumps(body).encode('utf-8'))
        content_json = json.loads(content)
        if resp["status"] != '200':
            raise Exception("%s\n" % content_json['message'])
        token = content_json["data"]["token"]["key"]
        projects = content_json["data"]["projects"]
        project_id = None
        if project_name:
            for project in projects:
                if project_name == project['name']:
                    project_id = project['id']
                    break
        else:
            project_id = projects[0]['id']
        if not project_id:
            raise Exception("User is not having access to Project '%s' or "
                            "project name is invalid\n" % project_name)
        return token, project_id
    except Exception as e:
        sys.stderr.write('Authentication Failed: %s\n' % e.message)
        exit(1)


def is_json(json_value):
    """ json validation fuction """
    try:
        json_file = open(json_value, 'r')
        json_val = json_file.read()
        json.loads(json_val)
        json_file.close()
        return True
    except Exception:
        sys.stderr.write("%s%s" % (json_value, " is invalid json \n"))
        exit(1)


def is_yaml(yaml_value):
    """ yaml validation fuction """
    try:
        yaml_file = open(yaml_value, 'r')
        yaml_val = yaml_file.read()
        yaml.safe_load(yaml_val)
        yaml_file.close()
        return True
    except Exception:
        sys.stderr.write("%s%s" % (yaml_value, " is invalid yaml \n"))
        exit(1)


def validate_files(resource_type, path, load_type, resources, skip_customer_resources=False):
    """ Validation of files """
    try:
        # Declarations
        validation_messages = []
        json_files = []
        valid_contentfiles = []
        valid_jsonfiles = []
        # Get the json files
        if load_type == 'A' or load_type == 'a':
            json_files = get_files(path, resource_type, skip_customer_resources)
        else:
            resources = (resources.split(","))
            for folder in resources:
                print folder
                folder_path = "%s%s" % (path, folder)
                resource_values = get_files(folder_path, resource_type, skip_customer_resources)
                for value in resource_values:
                    json_files.append(value)
        # File exist check
        for file_name in json_files:
            content_type = ""
            filename = file_name.replace(".json", "")

            # metadata file availabilty check
            if not os.path.exists(file_name):
                validation_messages.append(
                    filename + ' file not available please check and '
                               'Rerun the Resource Loader')

            # json validation for metadata
            if is_json(filename + '.json'):
                valid_jsonfiles.append(filename + '.json')
            else:
                validation_messages.append(filename + '.json file is not valid')

            if resource_type == "template":
                # content file availability check
                if os.path.exists(filename + '_content.yaml'):
                    content_type = ".yaml"
                elif os.path.exists(filename + '_content.json'):
                    content_type = ".json"
                elif os.path.exists(os.path.join(os.path.abspath(os.path.join(file_name, os.pardir)), 'content_files')):
                    content_type = "files"
                else:
                    validation_messages.append(
                        filename + '_content file not available, '
                                   'please check and Rerun the Resource Loader')
                # json validation & yaml validation for content
                if content_type == ".json":
                    if is_json(filename + '_content.json'):
                        valid_contentfiles.append(filename + '_content.json')
                    else:
                        valid_jsonfiles.remove(filename + '.json')
                        validation_messages.append(
                            filename + '_content.json file is not valid')
                elif content_type == ".yaml":
                    if is_yaml(filename + '_content.yaml'):
                        valid_contentfiles.append(filename + '_content.yaml')
                    else:
                        valid_jsonfiles.remove(filename + '.json')
                        validation_messages.append(
                            filename + '_content.yaml file is not valid')
                elif content_type == "files":
                    path = os.path.join(os.path.abspath(os.path.join(file_name, os.pardir)), 'content_files')
                    if not os.path.isdir(path) or not os.listdir(path):
                        valid_jsonfiles.remove(filename + '.json')
                        validation_messages.append(
                            filename + 'content files are not available')
                    else:
                        valid_contentfiles.append(path)
        if resource_type == "template":
            return validation_messages, valid_jsonfiles, valid_contentfiles
        else:
            return validation_messages, valid_jsonfiles

    except Exception as e:
        sys.stdout.write(e.message)
        exit(1)


def get_only_files(path):
    file_list = list()
    for elem in os.listdir(path):
        if os.path.isfile(os.path.join(path, elem)):
            file_list.append(elem)
    return file_list


def get_file_content(file_path):
    with open(file_path, 'r') as f:
        content = f.read()
    return content


def get_content_files(path):
    contents = dict(files=list())
    file_names = get_only_files(path)
    if 'main.tf' in file_names:
        contents['content'] = {"content": get_file_content(os.path.join(path, 'main.tf')), "name": "main.tf"}
        file_names.remove('main.tf')
    if 'variables.tf' in file_names:
        contents['variable'] = {"content": get_file_content(os.path.join(path, 'variables.tf')), "name": "variables.tf"}
        file_names.remove('variables.tf')
    if 'outputs.tf' in file_names:
        contents['output'] = {"content": get_file_content(os.path.join(path, 'outputs.tf')), "name": "outputs.tf"}
        file_names.remove('outputs.tf')
    for file_name in file_names:
        content_value = get_file_content(os.path.join(path, file_name))
        if 'content' not in contents and path.split('/')[-1] in file_name and file_name.endswith('.tf'):
            contents['content'] = {"content": content_value, "name": file_name}
        elif 'variable' not in contents and 'variable' in file_name and file_name.endswith('.tf'):
            contents['variable'] = {"content": content_value, "name": file_name}
        elif 'output' not in contents and 'output' in file_name and file_name.endswith('.tf'):
            contents['output'] = {"content": content_value, "name": file_name}
        else:
            contents['files'].append({"content": content_value, "name": file_name})
    return contents


def create_template(api_url, project_id, username, token, update_flag,
                    validation_messages, json_files, content_files, scope, csv_flag, input_list):
    """ This method call the template create api given the status of the each
        templates """
    try:
        # template loader log folder exists check
        log_path = '/opt/core/cache/tmp/templateloader_logs/'
        if not os.path.exists(log_path):
            os.makedirs(log_path)
        timestamp = datetime.datetime.fromtimestamp(
            time.time()).strftime('%Y%m%d%H%M%S')
        log_filename = 'templateloader_' + timestamp
        my_file = open(log_path + log_filename, "a")

        # Print and write the log messages
        for message in validation_messages:
            my_file.write("%s\n" % message)

        success_templates = 0

        for metadata, content in zip(json_files, content_files):
            # Metadata Read
            json_file = open(metadata, 'r')
            file_name = list(metadata.split("/"))
            file_name = file_name[-1]
            req_body = json.dumps(json_file.read()).encode('utf-8')
            req_body = json.loads(req_body)
            json_file.close()

            req_body = json.loads(req_body)

            if csv_flag:
                if input_list and req_body.get("name") not in input_list:
                    continue
            # Content Read
            if os.path.isfile(content):
                content_datafile = open(content, 'r')
                content_value = json.dumps(content_datafile.read()).encode('utf-8')
                content_value = json.loads(content_value)
                content_datafile.close()
                req_body["content_files"] = dict(content=dict(content=content_value, name=content.split('/')[-1]))
            else:
                req_body["content_files"] = get_content_files(content)
            # Checks for files
            files_directory = os.path.abspath(
                os.path.join(content, os.pardir)) + "/files"
            if os.path.exists(files_directory):
                dependencies = list()
                for script_file_path in find_files(files_directory, '*'):
                    script_file_name = os.path.basename(script_file_path)
                    script_file_obj = open(script_file_path, 'r')
                    script_file_value = script_file_obj.read()
                    script_file_obj.close()
                    dependencies.append({"content": script_file_value, "name": script_file_name})
                req_body["content_files"]["files"] = dependencies

            dependencies_directory = os.path.abspath(os.path.join(content, 'modules'))
            if os.path.exists(dependencies_directory):
                dependencies = list()
                for elem in os.listdir(dependencies_directory):
                    module_path = os.path.join(dependencies_directory, elem)
                    if not os.path.isdir(module_path):
                        continue
                    dependencies.append({"type": "module", "name": elem,
                                         "content_files": get_content_files(module_path)})
                if dependencies:
                    req_body['dependencies'] = dependencies
            if scope != 'default':
                req_body['scope'] = scope

            req_body = json.dumps(req_body).encode('utf-8')

            url = "%s%s/%s" % (api_url, project_id, 'templates')
            http_client = httplib2.Http()
            headers = {"X-Auth-User": username, "X-Auth-Token": token}

            # call the Create Template API
            resp, content = http_client.request(
                url, method="POST", body=req_body, headers=headers)
            content = json.loads(content)

            if resp["status"] == "200":
                success_templates += 1
                log_msg = "%s%s%s - %s" % (file_name[:-5], " ==> status:",
                                           content["status"],
                                           content["message"])
                sys.stdout.write("%s\n" % log_msg)
            elif resp["status"] == "400" and update_flag:
                template_id = None
                url = "%s%s/%s" % (api_url, project_id, 'templates')
                list_resp, list_content = http_client.request(
                    url, method="GET", headers=headers)
                list_content = json.loads(list_content)
                if list_resp["status"] == "200":
                    template_list = list_content['data']['templates']
                    for template in template_list:
                        if template['name'] == json.loads(req_body)['name']:
                            # call the Update Template API
                            template_id = template["id"]
                            url = "%s%s/%s/%s" % (api_url, project_id,
                                                  'templates', template_id)
                            update_resp, update_content = \
                                http_client.request(url, method="PUT",
                                                    body=req_body,
                                                    headers=headers)
                            update_content = json.loads(update_content)
                            log_msg = "%s%s%s - %s" % (
                                file_name[:-5], " ==> status:",
                                update_content["status"],
                                update_content["message"])
                            sys.stdout.write("%s\n" % log_msg)
                            if update_resp["status"] == "200":
                                success_templates += 1
                            break
                if not template_id:
                    temp_url = "%s%s/%s?is_temp=true" % (api_url, project_id, 'templates')
                    list_temp_resp, list_temp_content = http_client.request(
                        temp_url, method="GET", headers=headers)
                    list_temp_content = json.loads(list_temp_content)
                    if list_temp_resp["status"] == "200":
                        temp_template_list = list_temp_content['data']['templates']
                        for template in temp_template_list:
                            if template['name'] == json.loads(req_body)['name']:
                                # call the Update Template API
                                template_id = template["id"]
                                url = "%s%s/%s/%s" % (api_url, project_id,
                                                      'templates', template_id)
                                update_resp, update_content = \
                                    http_client.request(url, method="PUT",
                                                        body=req_body,
                                                        headers=headers)
                                update_content = json.loads(update_content)
                                log_msg = "%s%s%s - %s" % (
                                    file_name[:-5], " ==> status:",
                                    update_content["status"],
                                    update_content["message"])
                                sys.stdout.write("%s\n" % log_msg)
                                if update_resp["status"] == "200":
                                    success_templates += 1
                                break
                if not template_id:
                    log_msg = "%s%s%s - %s" % (file_name[:-5], " ==> status:",
                                               content["status"],
                                               content["message"])
                    sys.stderr.write("%s\n" % log_msg)
                    my_file.write("%s\n" % log_msg)
            else:
                log_msg = "%s%s%s - %s" % (file_name[:-5], " ==> status:",
                                           content["status"],
                                           content["message"])
                sys.stderr.write("%s\n" % log_msg)
                my_file.write("%s\n" % log_msg)
        if not csv_flag:
            total_templates = len(json_files)
            failed_templates = total_templates - success_templates
        else:
            total_templates = len(input_list)
            failed_templates = total_templates - success_templates
        sys.stdout.write('Total templates: ' + str(total_templates) + "\n")
        sys.stdout.write("Success Templates: " + str(success_templates) + "\n")
        sys.stderr.write("Failed Templates: " + str(failed_templates) + "\n")

        my_file.write('Total templates: ' + str(total_templates) + "\n")
        my_file.write("Failed Templates: " + str(failed_templates) + "\n")
        my_file.close()

    except Exception as e:
        sys.stdout.write(e.message)
        exit(1)


def create_script(api_url, project_id, username, token, update_flag,
                  validation_messages, json_files, scope, csv_flag, input_list):
    """ This method call the script create api given the status of the each
        scripts """
    try:
        # script loader log folder exists check
        log_path = '/opt/core/cache/tmp/scriptloader_logs/'
        if not os.path.exists(log_path):
            os.makedirs(log_path)

        timestamp = datetime.datetime.fromtimestamp(
            time.time()).strftime('%Y%m%d%H%M%S')
        log_filename = 'scriptloader_' + timestamp
        my_file = open(log_path + log_filename, "a")

        # Print and write the log messages
        for message in validation_messages:
            my_file.write("%s\n" % message)

        success_scripts = 0

        for metadata in json_files:
            # metadata Read
            json_file = open(metadata, 'r')
            file_name = list(metadata.split("/"))
            file_name = file_name[-1]
            req_body = json.dumps(json_file.read()).encode('utf-8')
            req_body = json.loads(req_body)
            json_file.close()
            req_body = json.loads(req_body)

            if csv_flag:
                if input_list and req_body.get("name") not in input_list:
                    continue
            if scope != 'default':
                req_body['scope'] = scope

            req_body = json.dumps(req_body).encode('utf-8')

            url = "%s%s/%s" % (api_url, project_id, 'scripts')
            http_client = httplib2.Http()
            headers = {"X-Auth-User": username, "X-Auth-Token": token}

            # call the create script API
            resp, content = http_client.request(
                url, method="POST", body=req_body, headers=headers)
            content = json.loads(content)

            if resp["status"] == "200":
                success_scripts += 1
                log_msg = "%s%s%s - %s" % (file_name[:-5], " ==> status:",
                                           content["status"],
                                           content["message"])
                sys.stdout.write("%s\n" % log_msg)
            elif resp["status"] == "400" and update_flag:
                script_id = None
                url = "%s%s/%s" % (api_url, project_id, 'scripts')
                list_resp, list_content = http_client.request(
                    url, method="GET", headers=headers)
                list_content = json.loads(list_content)
                if list_resp["status"] == "200":
                    script_list = list_content['data']['scripts']
                    for script in script_list:
                        if script['name'] == json.loads(req_body)['name']:
                            script_id = script["id"]
                            url = "%s%s/%s/%s" % \
                                  (api_url, project_id, 'scripts', script_id)
                            # call the update script API
                            update_resp, update_content = \
                                http_client.request(url, method="PUT",
                                                    body=req_body,
                                                    headers=headers)
                            update_content = json.loads(update_content)
                            log_msg = "%s%s%s - %s" % (
                                file_name[:-5], " ==> status:",
                                update_content["status"],
                                update_content["message"])
                            sys.stdout.write("%s\n" % log_msg)
                            if update_resp["status"] == "200":
                                success_scripts += 1
                            break
                if not script_id:
                    log_msg = "%s%s%s - %s" % (file_name[:-5], " ==> status:",
                                               content["status"],
                                               content["message"])
                    sys.stderr.write("%s\n" % log_msg)
                    my_file.write("%s\n" % log_msg)
            else:
                log_msg = "%s%s%s - %s" % (file_name[:-5], " ==> status:",
                                           content["status"],
                                           content["message"])
                sys.stderr.write("%s\n" % log_msg)
                my_file.write("%s\n" % log_msg)

        if not csv_flag:
            total_scripts = len(json_files)
            failed_scripts = total_scripts - success_scripts
        else:
            total_scripts = len(input_list)
            failed_scripts = total_scripts - success_scripts
        sys.stdout.write('Total Scripts: ' + str(total_scripts) + "\n")
        sys.stdout.write("Success Scripts: " + str(success_scripts) + "\n")
        sys.stdout.write("Failed Scripts: " + str(failed_scripts) + "\n")

        my_file.write('Total Scripts: ' + str(total_scripts) + "\n")
        my_file.write("Failed Scripts: " + str(failed_scripts) + "\n")
        my_file.close()

    except Exception as e:
        sys.stdout.write(e.message)
        exit(1)


def create_policy(api_url, project_id, username, token, update_flag, validation_messages, json_files, scope, csv_flag,
                  input_list):
    """ This method call the policy create/update api and return the status of the each policies """
    try:
        # policy loader log folder exists check
        log_path = '/opt/core/cache/tmp/policyloader_logs/'
        if not os.path.exists(log_path):
            os.makedirs(log_path)
        timestamp = datetime.datetime.fromtimestamp(time.time()).strftime('%Y%m%d%H%M%S')
        log_filename = 'policyloader_' + timestamp
        my_file = open(log_path + log_filename, "a")

        # Print and write the log messages
        for message in validation_messages:
            my_file.write("%s\n" % message)

        success_policies = 0

        for metadata in json_files:
            # metadata Read
            json_file = open(metadata, 'r')
            file_name = list(metadata.split("/"))
            file_name = file_name[-1]
            req_body = json.dumps(json_file.read()).encode('utf-8')
            req_body = json.loads(req_body)
            json_file.close()

            req_body = json.loads(req_body)
            if csv_flag:
                if input_list and req_body.get("name") not in input_list:
                    continue

            if scope != 'default':
                req_body['scope'] = scope

            req_body = json.dumps(req_body).encode('utf-8')

            url = "%s%s/%s" % (api_url, project_id, 'policies')
            http_client = httplib2.Http()
            headers = {"X-Auth-User": username, "X-Auth-Token": token}

            # call the create policy API
            resp, content = http_client.request(url, method="POST", body=req_body, headers=headers)
            content = json.loads(content)

            if resp["status"] == "200":
                success_policies += 1
                log_msg = "%s%s%s - %s" % (file_name[:-5], " ==> status:", content["status"], content["message"])
                sys.stdout.write("%s\n" % log_msg)
            elif resp["status"] == "400" and update_flag:
                policy_id = None
                url = "%s%s/%s" % (api_url, project_id, 'policies')
                list_resp, list_content = http_client.request(url, method="GET", headers=headers)
                list_content = json.loads(list_content)
                if list_resp["status"] == "200":
                    policy_list = list_content['data']['policies']
                    for policy in policy_list:
                        if policy['name'] == json.loads(req_body)['name']:
                            policy_id = policy["id"]
                            url = "%s%s/%s/%s" % (api_url, project_id, 'policies', policy_id)
                            # call the update policy API
                            update_resp, update_content = http_client.request(url, method="PUT", body=req_body,
                                                                              headers=headers)
                            update_content = json.loads(update_content)
                            log_msg = "%s%s%s - %s" % (file_name[:-5], " ==> status:", update_content["status"],
                                                       update_content["message"])
                            sys.stdout.write("%s\n" % log_msg)
                            if update_resp["status"] == "200":
                                success_policies += 1
                            break
                if not policy_id:
                    policy_url = "%s%s/%s?is_temp=true" % (api_url, project_id, 'policies')
                    list_resp, list_content = http_client.request(policy_url, method="GET", headers=headers)
                    list_content = json.loads(list_content)
                    if list_resp["status"] == "200":
                        temp_policy_list = list_content['data']['policies']
                        for policy in temp_policy_list:
                            if policy['name'] == json.loads(req_body)['name']:
                                # call the Update policy API
                                policy_id = policy["id"]
                                url = "%s%s/%s/%s" % (api_url, project_id, 'policies', policy_id)
                                update_resp, update_content = \
                                    http_client.request(url, method="PUT", body=req_body, headers=headers)
                                update_content = json.loads(update_content)
                                log_msg = "%s%s%s - %s" % (file_name[:-5], " ==> status:", update_content["status"],
                                                           update_content["message"])
                                sys.stdout.write("%s\n" % log_msg)
                                if update_resp["status"] == "200":
                                    success_policies += 1
                                break
                if not policy_id:
                    log_msg = "%s%s%s - %s" % (file_name[:-5], " ==> status:", content["status"], content["message"])
                    sys.stderr.write("%s\n" % log_msg)
                    my_file.write("%s\n" % log_msg)
            else:
                log_msg = "%s%s%s - %s" % (file_name[:-5], " ==> status:", content["status"], content["message"])
                sys.stderr.write("%s\n" % log_msg)
                my_file.write("%s\n" % log_msg)

        if not csv_flag:
            total_policies = len(json_files)
            failed_policies = total_policies - success_policies
        else:
            total_policies = len(input_list)
            failed_policies = total_policies - success_policies

        sys.stdout.write('Total Policies: ' + str(total_policies) + "\n")
        sys.stdout.write("Success Policies: " + str(success_policies) + "\n")
        sys.stdout.write("Failed Policies: " + str(failed_policies) + "\n")

        my_file.write('Total Policies: ' + str(total_policies) + "\n")
        my_file.write("Failed Policies: " + str(failed_policies) + "\n")
        my_file.close()

    except Exception as e:
        sys.stdout.write(e.message)
        exit(1)


def create_blueprint(api_url, project_id, username, token, update_flag, json_files):
    try:
        # Blueprint loader log folder exists check
        log_path = '/opt/core/cache/tmp/blueprint_loader_log/'
        if not os.path.exists(log_path):
            os.makedirs(log_path)

        timestamp = datetime.datetime.fromtimestamp(
            time.time()).strftime('%Y%m%d%H%M%S')
        log_filename = 'blueprint_loader_' + timestamp
        my_file = open(log_path + log_filename, "a")

        success_blueprints = 0

        for metadata in json_files:
            json_file = open(metadata, 'r')
            file_name = list(metadata.split("/"))
            file_name = file_name[-1]
            req_body = json.dumps(json_file.read()).encode('utf-8')
            req_body = json.loads(req_body)
            json_file.close()
            req_body = json.loads(req_body)

            http_client = httplib2.Http()
            headers = {"X-Auth-User": username, "X-Auth-Token": token}
            try:
                for resource in req_body['resources']:
                    url = "%s%s/%s" % (api_url, project_id, 'templates?action=get_templateid')
                    template_req = {'template_names': [resource['name']]}
                    template_req = json.dumps(template_req).encode('utf-8')

                    # Get template id
                    resp, content = http_client.request(
                        url, method="POST", body=template_req, headers=headers)
                    template_details = json.loads(content)
                    if resp["status"] == "200":
                        resource['id'] = template_details['data'][0]['template_id']
                    else:
                        log_msg = "%s%s%s - %s" % (file_name[:-5], " ==> status:",
                                                   template_details["status"],
                                                   template_details["message"])
                        sys.stderr.write("%s\n" % log_msg)
                        my_file.write("%s\n" % log_msg)
                        raise Exception('Unable to get template details for %s' % resource['name'])
            except Exception as e:
                sys.stderr.write(e.message)
                continue

            req_body = json.dumps(req_body).encode('utf-8')
            url = "%s%s/%s" % (api_url, project_id, 'blueprints')

            # call the create blueprint API
            resp, content = http_client.request(
                url, method="POST", body=req_body, headers=headers)
            content = json.loads(content)

            if resp["status"] == "200":
                success_blueprints += 1
                log_msg = "%s%s%s - %s" % (file_name[:-5], " ==> status:",
                                           content["status"],
                                           content["message"])
                sys.stdout.write("%s\n" % log_msg)
            elif resp["status"] == "400" and update_flag:
                blueprint_id = None
                url = "%s%s/%s" % (api_url, project_id, 'blueprints')
                list_resp, list_content = http_client.request(
                    url, method="GET", headers=headers)
                list_content = json.loads(list_content)
                if list_resp["status"] == "200":
                    blueprint_list = list_content['data']['blueprints']
                    for blueprint in blueprint_list:
                        if blueprint['name'] == json.loads(req_body)['name']:
                            blueprint_id = blueprint["id"]
                            url = "%s%s/%s/%s" % \
                                  (api_url, project_id, 'blueprints', blueprint_id)
                            # call the update blueprint API
                            update_resp, update_content = \
                                http_client.request(url, method="PUT",
                                                    body=req_body,
                                                    headers=headers)
                            update_content = json.loads(update_content)
                            log_msg = "%s%s%s - %s" % (
                                file_name[:-5], " ==> status:",
                                update_content["status"],
                                update_content["message"])
                            sys.stdout.write("%s\n" % log_msg)
                            if update_resp["status"] == "200":
                                success_blueprints += 1
                            break
                if not blueprint_id:
                    log_msg = "%s%s%s - %s" % (file_name[:-5], " ==> status:",
                                               content["status"],
                                               content["message"])
                    sys.stderr.write("%s\n" % log_msg)
                    my_file.write("%s\n" % log_msg)
            else:
                log_msg = "%s%s%s - %s" % (file_name[:-5], " ==> status:",
                                           content["status"],
                                           content["message"])
                sys.stderr.write("%s\n" % log_msg)
                my_file.write("%s\n" % log_msg)

        total_blueprints = len(json_files)
        failed_blueprints = total_blueprints - success_blueprints
        sys.stdout.write('Total Blueprints: ' + str(total_blueprints) + "\n")
        sys.stdout.write("Success Blueprints: " + str(success_blueprints) + "\n")
        sys.stdout.write("Failed Blueprints: " + str(failed_blueprints) + "\n")

        my_file.write('Total Blueprints: ' + str(total_blueprints) + "\n")
        my_file.write("Failed Blueprints: " + str(failed_blueprints) + "\n")
        my_file.close()

    except Exception as e:
        sys.stdout.write(e.message)
        exit(1)


def load_resources():
    try:
        csv_flag = 0
        input_list = list()

        api_url, username, password, resource_type, path, load_type, resources, update_flag, project_name, scope, \
        csv, skip_customer_resources = config_detail()

        if skip_customer_resources.lower() in ['yes', 'y']:
            skip_customer_resources = True
        else:
            skip_customer_resources = False

        token, project_id = api_authenticate(username, password, api_url, project_name)
        if csv:
            csv_flag = 1
            input_list = load_template_path_from_csv(csv, col_name=resource_type)

        if resource_type == "template":
            validation_messages, json_files, content_files = validate_files(resource_type, path, load_type, resources
                                                                            )
            create_template(api_url, project_id, username, token, update_flag, validation_messages, json_files,
                            content_files, scope, csv_flag, input_list)
        elif resource_type == "blueprint":
            template_validation_messages, template_json_files, template_content_files = \
                validate_files('template', path, load_type, resources, skip_customer_resources)
            create_template(api_url, project_id, username, token, update_flag, template_validation_messages,
                            template_json_files, template_content_files, scope, csv_flag, input_list)
            validation_messages, json_files = validate_files(resource_type, path, load_type, resources,
                                                             skip_customer_resources)
            create_blueprint(api_url, project_id, username, token, update_flag, json_files)
        else:
            validation_messages, json_files = validate_files(resource_type, path, load_type, resources)
            if resource_type == "policy":
                create_policy(api_url, project_id, username, token, update_flag, validation_messages, json_files, scope,
                              csv_flag, input_list)
            else:
                create_script(api_url, project_id, username, token, update_flag, validation_messages, json_files, scope,
                              csv_flag, input_list)
    except Exception as e:
        sys.stdout.write(e.message)
        exit(1)


if __name__ == '__main__':
    load_resources()
