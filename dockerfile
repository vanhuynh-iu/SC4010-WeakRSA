FROM python:3.12-slim

WORKDIR /project

RUN pip install --no-cache-dir pycryptodome pandas matplotlib dataframe_image

CMD ["bash"]