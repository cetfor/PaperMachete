import sys
import subprocess
import os
from os.path import abspath, isdir, isfile, join, splitext
from mimetypes import guess_type
from urllib2 import urlopen
from ast import literal_eval
import pmanalyze

ENTER = '\nPress ENTER to continue'
MACHETE = abspath('.')
query_path = join(MACHETE, "queries")
ANALYSIS = join(MACHETE, "analysis")

MAX_ACTIVE = 25     # migration knob: max number of migration workers running at once
MAX_BATCHES = 1000000000   # migration knob: max number of rows to execute in one transation

MENU1 = "[1] Analyze a binary file"
MENU2 = "[2] Migrate a JSON file into Grakn"
MENU3 = "[3] Run all CWE queries"
MENU4 = "[4] Clean and restart Grakn"
MENU5 = "[5] Quit"

TEMPLATE_DESC = [
    '', # n/a
    'Migrating functions.',                         # template 1
    'Migrating basic-blocks.',                      # template 2
    'Linking basic-blocks to their functions.',     # template 3
    'Migrating instructions.',                      # template 4
    'Linking instructions to their basic-blocks.',  # template 5
    'Migrating all AST nodes.',                     # template 6
    'Linking AST nodes.'                            # template 7
]

def print_banner(title=""):
    subprocess.call("clear")
    print("""
 ____                        __  __            _          _
|  _ \ __ _ _ __  ___ _ __  |  \/  | __ _  ___| |__   ___| |_ ___    ________
| |_) / _` | '_ \/ _ \ '__| | |\/| |/ _` |/ __| '_ \ / _ \ __/ _ \  /_______/
|  __/ (_| | |_)|  __/ |    | |  | | (_| | (__| | | |  __/ ||  __/  \_______\\
|_|   \__,_| .__/\___|_|    |_|  |_|\__,_|\___|_| |_|\___|\__\___|  /_______/
           |_|                                                     @==|;;;;;;>
""")
    total_len = 80
    if title:
        padding = total_len - len(title) - 4
        print("== {} {}\n".format(title, "=" * padding))
    else:
        print("{}\n".format("=" * total_len))

def run_script(query_path, query, keyspace):
    try:
        subprocess.call(["python3.6", join(query_path, query), keyspace])
    except OSError:
        print("It looks like you don't have Python3.6 installed. " \
            "The Grakn Python driver requires it.")
        return -1
    return 0

def run_queries(query, keyspace):
    if query == 'all_queries':
        print("Running all CWE queries against the '{}' keyspace...".format(keyspace))
        queries = [f for f in os.listdir(query_path) if isfile(join(query_path, f))]
        for query in queries:
            if ".py" not in query: continue
            if run_script(query_path, query, keyspace): return
            print("Script " + query + " complete.")
        print("All queries complete.")
    else:
        if isfile(join(query_path, query)):
            if run_script(query_path, query, keyspace): return
        else:
            print("Could not find the python script " + query)
            print("Please make sure it is located in " + query_path)
        return


def get_file_selection(types):
    file_list = os.listdir(ANALYSIS)
    filtered = []
    for file in file_list:
        if types == "json" and guess_type(join(ANALYSIS, file))[0] == "application/json":
            filtered.append(file)
        elif types == "bin":
            filecmd = (subprocess.check_output(["file", join(ANALYSIS, file)])).lower()
            filecmd = filecmd.split(": ")[1] # remove file path returned by 'file' utility
            if "elf" in filecmd or "mach-o" in filecmd or "pe" in filecmd or ".bndb" in file.lower():
                filtered.append(file)
        else:
            pass # not json or executable binary

    # print file choices
    if len(filtered) == 0:
        if types == "json":
            print("No json files were found in {}".format(ANALYSIS))
        elif types == "bin":
            print("No executable files were found in {}".format(ANALYSIS))
        raw_input(ENTER)
        return "quit"
    else:
        for i, file in enumerate(filtered):
            print "[{}] {}".format(i, file)

    index = raw_input("\nSelect a file number to analyze ([q]uit): ").lower()
    if index == "q" or index == "quit":
        return "quit"

    try:
        index = int(index)
        if index in range(0, len(filtered)):
            return filtered[int(index)]
    except ValueError:
        pass

    if index != "":
        print("\nThat is not a valid file selection. Try again.")
        raw_input(ENTER)
    if types == "bin":
        print_banner(MENU1)
    elif types == "json":
        print_banner(MENU2)
    else:
        print_banner()

    return False


def main():
    menu = True
    while menu:
        print_banner()

        # check directories
        try:
            subprocess.call(['grakn', 'version'], stdout=open(os.devnull, 'wb'))
            subprocess.call(['graql', 'version'], stdout=open(os.devnull, 'wb'))
        except OSError:
            print("Please ensure grakn and graql are in your PATH")
            sys.exit()

        if not isdir(MACHETE):
            print("Paper Machete directory not found")
            print("Please ensure Paper Machete is located in {}".format(MACHETE))
            sys.exit()

        if not isdir(ANALYSIS):
            print("Creating directory '{}'".format(ANALYSIS))
            subprocess.call(["mkdir", "analysis"])

        menu_option = raw_input("{}\n{}\n{}\n{}\n{}\n\n>> ".format(MENU1,MENU2,MENU3,MENU4,MENU5))

        try:
            menu_option = int(menu_option)
        except ValueError:
            if menu_option != "":
                print("'{}' is not a valid option.".format(menu_option))
                raw_input(ENTER)
            continue

        # analyze a binary file
        if menu_option == 1:

            # display supported binary files in ./analysis
            binary = False
            while binary == False:
                print_banner(MENU1)
                binary = get_file_selection("bin")
                if binary == "quit":
                    break
            if binary == "quit":
                continue

            # check to see if the file exists, if it does, process it
            if not isfile(join(ANALYSIS, binary)):
                print("File '{}' not found.".format(binary))
            else:
                functions = str(raw_input('Specify a list of functions examine seperated by spaces (ENTER for all): ')).split()
                if len(functions) == 0:
                    pmanalyze.main(join(ANALYSIS, binary))
                else:
                    print functions
                    pmanalyze.main(join(ANALYSIS, binary), functions)
            raw_input(ENTER)

        # migrate a json file into Grakn
        elif menu_option == 2:

            # display supported binary files in ./analysis
            json = False
            while json == False:
                print_banner(MENU2)
                json = get_file_selection("json")
                if json == "quit":
                    break
            if json == "quit":
                continue

            # check to see if the keyspace already exists for this file
            try:
                keyspace = json.lower().replace('.json', '')
                keyspaces = literal_eval(urlopen('http://127.0.0.1:4567/kb').read())

                inc = 1
                finding_name = True
                while finding_name:
                    inc += 1
                    if keyspace not in keyspaces:
                        finding_name = False # keyspace name is not in use
                    else:
                        keyspace = "{}_{}".format(keyspace, inc) # add a _# suffix and try again
            except:
                print("Unable to query keyspace names. Is Grakn running?\nContinuing assuming keyspace '{}' is OK to use.".format(keyspace))

            try:
                # insert the ontology
                print("Inserting ontology into the '{}' keyspace...".format(keyspace))
                subprocess.call(["graql","console", "-f", join(MACHETE, "templates", "binja_mlil_ssa.gql"), "-k", keyspace])


                # migrate data into Grakn
                print("\nMigrating data from '{}' into the '{}' keyspace...".format(json, keyspace))

                # loop over all 7 templates
                for num in range(1,8):
                    print(">> Migration step {} of 7: {}".format(num, TEMPLATE_DESC[num]))
                    subprocess.call(["graql", "migrate", "json", "--template", join(MACHETE, "templates", "binja_mlil_ssa_{}.tpl".format(num)), "--input", join(ANALYSIS, json), "--keyspace", keyspace])

                print("Data successfully migrated into Grakn. You can now run CWE query scripts against '{}' to check for vulnerabilities".format(keyspace))
                raw_input(ENTER)
            except:
                print("Upload failed... please try agin.")
                raw_input(ENTER)

        # run CWE queries
        elif menu_option == 3:
            keyspace = None
            keyspaces = literal_eval(urlopen('http://127.0.0.1:4567/kb').read())['keyspaces']

            print_banner(MENU3)

            for i, ks in enumerate(keyspaces):
                print("[{}] {}".format(i, ks['name']))

            index = raw_input("\nSelect a keyspace to run all queries against ([q]uit): ").lower()
            if index == "q" or index == "quit":
                continue

            try:
                index = int(index)
                if index in range(0, len(keyspaces)):
                    keyspace = keyspaces[int(index)]['name']
            except ValueError:
                continue

            run_queries('all_queries', keyspace)
            raw_input(ENTER)

        # clean and restart Grakn
        elif menu_option == 4:
            print("Restarting Grakn. Press \"Y\" when prompted.\nWait until you see the Grakn banner before continuing!")
            raw_input(ENTER)

            subprocess.call(["grakn", "server", "stop"])
            subprocess.call(["grakn", "server", "clean"])
            subprocess.call(["grakn", "server", "start"])

        # quit
        elif menu_option == 5:
            menu = False

        else:
            print("Invalid option!\n")
            raw_input(ENTER)

if __name__ == "__main__":
    main()
