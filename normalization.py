# coding=utf-8
import re, os
import glob
import argparse
from clean_gadget import clean_gadget


def parse_options():
    parser = argparse.ArgumentParser(description='Normalization.')
    parser.add_argument('-i', '--input', help='The input dir path of dataset, including a set of .c files.', type=str,
                        required=True)
    parser.add_argument('-o', '--output', help='The output dir path of dataset, to save a set of normalized .c files.',
                        type=str, required=True)
    parser.add_argument('-l', '--local', help='The output dir path of var/fun, to save a set of local var/fun and correspondent name.',
                        type=str, required=True)
    args = parser.parse_args()
    return args


def normalize(filepath, savepath,localpath):
    with open(filepath, "r") as file:
        code = file.read()
    file.close()
    code = re.sub('(?<!:)\\/\\/.*|\\/\\*(\\s|.)*?\\*\\/', "", code)
    with open(savepath, "w") as file:
        file.write(code.strip())
    file.close()

    with open(savepath, "r") as file:
        org_code = file.readlines()
        nor_code = clean_gadget(org_code,localpath,savepath)
    file.close()

    with open(savepath, "w") as file:
        file.writelines(nor_code)
    file.close()


def main():
    args = parse_options()
    input_path = args.input

    output_path = args.output

    local_path = args.local
    input_path = input_path + "/" if input_path[-1] != "/" else input_path
    output_path = output_path + "/" if output_path[-1] != "/" else output_path
    local_path = local_path + "/" if local_path[-1] != "/" else local_path



    if not os.path.exists(output_path):
        os.makedirs(output_path)
    if not os.path.exists(local_path):
        os.makedirs(local_path)
    file_dict = glob.glob(input_path + "*.*") 

    for file in file_dict:
        savefile = output_path + file.split("/")[-1]

        savefile = savefile+ ".c"
        print("savefile",savefile)

        localfile = local_path + file.split("/")[-1]
        localfile = localfile + ".txt"


        normalize(file, savefile, localfile)


if __name__ == '__main__':
    main()


