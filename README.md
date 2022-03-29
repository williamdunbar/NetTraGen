# NETTRAGEN

Là một sản phẩm demo của nhóm học viên HVKTQS

## Installation

Trong sản phẩm này chúng tôi dùng pipenv và virtualenv.
Để cài đặt và chạy ứng dụng cần làm như sau

```bash
pip install pipenv
pipenv shell
pipenv install -r requirement.txt
uvicorn main:app --reload
```