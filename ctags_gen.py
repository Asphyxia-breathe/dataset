import os
import argparse
import subprocess
import re
def parse_options():
    parser = argparse.ArgumentParser(description='Extracting diff.')
    parser.add_argument('-i', '--input', help='The dir path of input', type=str)
    parser.add_argument('-o', '--output', help='The dir path of output', type=str)
    args = parser.parse_args()
    return args


def ctags_gen(input_folder, output_folder):

    for root, dirs, files in os.walk(input_folder):
        for file in files:
            if file.endswith('.c') or file.endswith('.cpp'):

                input_file = os.path.join(root, file)

 
                file_name = os.path.splitext(file)[0]
                if file_name.endswith("_NEW"):
                    file_name = file_name[:-4]

     
                output_file = os.path.join(output_folder, file_name)

       
                command = f'ctags -o "{output_file}" --kinds-C=* --fields=neKSt "{input_file}"'
                print(command)
        
                return_code = os.system(command)
          
                if return_code == 0:
                    print(f"the file has been processed: {input_file}")
                else:
                    print(f"error: {input_file}")

def process_file(file_path):

    with open(file_path, 'r', encoding="utf-8") as file:
        lines = file.readlines()


    processed_lines = [line for line in lines if not line.strip().startswith('!')]
    for i in range(len(processed_lines)):
        line = processed_lines[i]
        words = line.split()
        print(words)
        if len(words) > 2:
            del words[1]


        processed_lines[i] = ' '.join(words)+'\n'


    with open(file_path, 'w', encoding="utf-8") as file:
        file.write(''.join(processed_lines))

def remove_special_text_inplace(file_path):
    with open(file_path, 'r+', encoding='utf-8') as f:
        content = f.read()

        cleaned_content = re.sub(r'/\^[^\n]+"', '', content)
        f.seek(0)
        f.write(cleaned_content)
        f.truncate()


def main():
    args = parse_options()
    input_folder = args.input
    output_folder = args.output
    os.makedirs(output_folder, exist_ok=True)
    ctags_gen(input_folder, output_folder)
    for filename in os.listdir(output_folder):
        file_path = os.path.join(output_folder, filename)
        process_file(file_path)
        remove_special_text_inplace(file_path)

    

if __name__ == "__main__":
    main()






