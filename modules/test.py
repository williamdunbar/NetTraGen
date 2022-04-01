import json
import os

def Json_Parse(name, age, sex,occupation):
    object = {}
    object["name"] = name
    object["age"] = age
    object["sex"] = sex
    object["occupation"] = occupation
    return json.dump(object)

def write_json(data, filename):
    cur_path = os.path.dirname(__file__)
    new_path = os.path.join(cur_path, '..', 'log', filename)
    print(new_path)
    with open(new_path,"w") as f:
        json.dump(data,f)

        
json = [
            {
                "name": "Ram",
                "age": "21",
                "sex": "Male",
                "occupation": "Doctor"
            },
            {
                "name": "Mohan",
                "age": "32",
                "sex": "Male",
                "occupation": "Teacher"
            },
            {
                "name": "Rani",
                "age": "42",
                "sex": "Female",
                "occupation": "Nurse"
            },
            {
                "name": "Johan",
                "age": "23",
                "sex": "Female",
                "occupation": "Software Engineer"
            },
            {
                "name": "Shajia",
                "age": "39",
                "sex": "Female",
                "occupation": "Farmer"
            }
];

# a = json.dumps(value1, indent=2)
# print(a)

# b = json.dumps(value2, indent=2)
# print(b)

# c = a +","+ b
# print(c)

# d = a +","+ c

my_data = [{'id': 1, 'name': 'Frank'}, {'id': 2, 'name': 'Rakesh'}]
print(my_data)