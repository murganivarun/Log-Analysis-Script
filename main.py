import os, sys
import csv
import apache_log_parser
import analysis

logfile_path = "SamplelogFile.txt"
parsed_csv_filename = "access_log.csv"
access_log_line_parser = apache_log_parser.make_parser("%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-agent}i\"")

class Application():
    def __init__(self):
        if (len(sys.argv) > 1) and sys.argv[1] == "parsing_required":
            print("Log file parsing started !")
            self.parse_log_file_to_csv()

        path_joiner = "\\" if sys.platform == "win32" else "/"
        csv_filepath = os.getcwd() + path_joiner + parsed_csv_filename

        if os.path.isfile(csv_filepath):
            analysis.Analysis(csv_filepath)
        else:
            print("Seems like Access Log File is not converted to CSV. Hence, analysis can't be done !")
            return


def parse_log_file_to_csv(self):
    faulty_lines = 0
    write_header = True
    total_line_counter = 0

    with open(logfile_path) as inFile, open(parsed_csv_filename, 'w', newline='') as outFile:
        log_line_data = {}
        lines = inFile.readlines()
        writer = csv.writer(outFile)

        for line in lines:
            total_line_counter += 1
            try:
                log_line_data = access_log_line_parser(line)
                if write_header:
                    writer.writerow(list(log_line_data.keys()))
                    write_header = False

                writer.writerow(list(log_line_data.values()))

            except Exception as ex:
                faulty_lines += 1
                print("The format specified does not match the line number {} of log file".format(total_line_counter))

    print("CSV file created having {} entries !".format(total_line_counter - faulty_lines))

if __name__=='__main__':
 Application()
