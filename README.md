# Хакатон VTB.

## Кейс: Инструмент обеспечения безопасности API
## Задача: Создать механизм извлечения и проверки вложенных объектов в сообщениях
### Команда k0b1x \ 2021.

### Вызовы:
- Учёт всевозможных видов атак: файловые бомбы, эксплоиты, вредоносные вложения;
- Проверка с минимальной задержкой;
- Сохранение сложной структуры после обработки;
- Парсинг и обработка сложной архитектура файлов;
- Неизвестная глубина и количество вложений;
- Нет конкретных примеров файлов;
- Работа в закрытом контуре без взаимодействия с внешними сервисами;
- Протоколирование и статистика обработанных файлов и вложений;

## Dashboard, панель администратора:
Кабинет администратора позволяет видеть статистику по объектам и вложениям, дате и времени проверки, хэшу файла и статусу проверки.
![alt text](https://github.com/progressionnetwork/vtb_handler/blob/main/screens/Screenshot1.png?raw=true)

## Что сделали на хакатоне:
- Создан веб сервис с бекендом и фронтендом, реализацией бизнес логики, которая взаимодействует с API банка для получения сообщений и передачи обработанных объектов.
- Создан генератор многоуровневых XML;
- Конфиг позволяет регулировать диапазон глубины вложенности, количество файлов, выбирать типы файлов для упаковки;
- Создан рекурсивный парсер  вложений xml;
- Парсер работает с любым уровнем вложенности, понимает любые виды тегов и достаёт файлы упакованные base64;
- Создан механизм проверки на вредоносы;
- Сигнатураня проверка Yara, проверка антивирусом ClamAV, эвристическая проверка по набору признаков и блеклисту;
- Создан механизм обратной сборки xml;
- Генерируется итоговый xml файл с учетом вложенности объектов;

## Механизм работы сервиса:
1. Встраивание в процесс обмена сообщениями по API
2. Получение сообщения по API и извлечение объекта(ов)
3. Парсинг XML, извлечение вложенных сущностей
4. Определение типов вложений, структурирование на уровне ФС
5. Распаковка архивов, вложенных файлов
6. Проверка потенциально вредононсных объектов и их удаление
7. Обратная сборка XML файла и передача в сообщения по API

## Механизмы проверки объектов:
- Сигнатурный поиск по базе вредоносов через Yara Engine
- Расширяемый набор правил, блеклистов по эвристическим правилам
- Подключение анивирусов для проверки извлеченных файлов
- Проверка макросов в офисных документах
- Использование black-листов, white-листов и middle-листов для прогнозирования

## Как улучшить решение?:
Планы на будущее...

- Внедрение ML алгоритмов проверки
- Динамическая проверка с запуском
- Реализация модели классификатора
- Горизонтальное масштабирование
- Расширенная статистика, аналитика, тренды

## Стек используемых технологий и библиотек:
- Python
- Yara Engine
- Json lib
- Django
- TAR Lib
- Redis
- XML Parser
- ClamAV Engine
- ZIP Lib
- 7z Lib
- Docker
- Vuejs lib
- Nginx
- Celery lib
- Django rest framework
- Axios
- PostgreSQL

## Сгенерированный xml файл со случайной вложенностью и случайными файлами:
![alt text](https://github.com/progressionnetwork/vtb_handler/blob/main/screens/Screenshot2.png?raw=true)


## Пример отчета от бизнес логики на бекенде:
```{
  "id": 0,
  "name": "",
  "path": "/home/app/web/api/services/vtb_handler/media/extracted/0_sample_GWA10L_JWKIg5o_10_14471625",
  "type": "directory",
  "children": [
    {
      "id": 0,
      "name": "string1",
      "path": "/home/app/web/api/services/vtb_handler/media/extracted/0_sample_GWA10L_JWKIg5o_10_14471625/string1",
      "type": "directory",
      "children": [
        {
          "id": 0,
          "ext": ".pdf",
          "md5": "e79b18aeadf57c9d558077c418887686",
          "name": "string156.pdf",
          "path": "/home/app/web/api/services/vtb_handler/media/extracted/0_sample_GWA10L_JWKIg5o_10_14471625/string1/string156.pdf",
          "sha1": "bdc11f1d7d9db7ab99c7005b633cd769270ed074",
          "size": 1744,
          "type": "file"
        }
      ]
    },
    {
      "id": 2,
      "name": "summary1",
      "path": "/home/app/web/api/services/vtb_handler/media/extracted/0_sample_GWA10L_JWKIg5o_10_14471625/summary1",
      "type": "directory",
      "children": [
        {
          "id": 2,
          "ext": ".json",
          "md5": "83619890385b01c25283362acea521dc",
          "name": "summary3396.json",
          "path": "/home/app/web/api/services/vtb_handler/media/extracted/0_sample_GWA10L_JWKIg5o_10_14471625/summary1/summary3396.json",
          "sha1": "8982ca6aa5486d4b17c0042c62d60af2edc0d204",
          "size": 15,
          "type": "file"
        },
        {
          "id": 3,
          "ext": ".jpg",
          "md5": "1958e6c927294b1258dae76aadcdcfea",
          "name": "summary2224.jpg",
          "path": "/home/app/web/api/services/vtb_handler/media/extracted/0_sample_GWA10L_JWKIg5o_10_14471625/summary1/summary2224.jpg",
          "sha1": "51caf5e4b8645ed177a38dc32f4f517a6e245bb4",
          "size": 58,
          "type": "file"
        }
      ]
    },
    {
      "id": 5,
      "name": "param7731_xml_12",
      "path": "/home/app/web/api/services/vtb_handler/media/extracted/0_sample_GWA10L_JWKIg5o_10_14471625/param7731_xml_12",
      "type": "directory",
      "children": [
        {
          "id": 5,
          "name": "param7731_10_14471625",
          "path": "/home/app/web/api/services/vtb_handler/media/extracted/0_sample_GWA10L_JWKIg5o_10_14471625/param7731_xml_12/param7731_10_14471625",
          "type": "directory",
          "children": [
            {
              "id": 5,
              "name": "file0",
              "path": "/home/app/web/api/services/vtb_handler/media/extracted/0_sample_GWA10L_JWKIg5o_10_14471625/param7731_xml_12/param7731_10_14471625/file0",
              "type": "directory",
              "children": [
                {
                  "id": 5,
                  "ext": ".zip",
                  "md5": "3ccffb6f410909e3b393796066cb1ab8",
                  "name": "file1768.zip",
                  "path": "/home/app/web/api/services/vtb_handler/media/extracted/0_sample_GWA10L_JWKIg5o_10_14471625/param7731_xml_12/param7731_10_14471625/file0/file1768.zip",
                  "sha1": "074159e350d24a0aeffd1f2a6e333515fdda0149",
                  "size": 9,
                  "type": "file"
                }
              ]
            }
          ]
        }
      ]
    },
   ....
    {
      "id": 35,
      "name": "text1",
      "path": "/home/app/web/api/services/vtb_handler/media/extracted/0_sample_GWA10L_JWKIg5o_10_14471625/text1",
      "type": "directory",
      "children": [
        {
          "id": 35,
          "ext": ".zip",
          "md5": "7fcb3e54633f1e0b3991f7020ec67b53",
          "name": "text1549.zip",
          "path": "/home/app/web/api/services/vtb_handler/media/extracted/0_sample_GWA10L_JWKIg5o_10_14471625/text1/text1549.zip",
          "sha1": "a2eba71cc906f077b512c0c88ab00b2796785269",
          "size": 55,
          "type": "file"
        },
        {
          "id": 36,
          "ext": ".json",
          "md5": "83619890385b01c25283362acea521dc",
          "name": "text1371.json",
          "path": "/home/app/web/api/services/vtb_handler/media/extracted/0_sample_GWA10L_JWKIg5o_10_14471625/text1/text1371.json",
          "sha1": "8982ca6aa5486d4b17c0042c62d60af2edc0d204",
          "size": 15,
          "type": "file"
        }
      ]
    }
  ],
  "xml_data": {
    "tags": [
      "text",
      "message",
      "assembly",
      "members",
      "meta",
      "data",
      "param",
      "summary",
      "string",
      "entry",
      "file",
      "tag",
      "root"
    ],
    "uniq_id": "10_14471625",
    "total_objects": 21,
    "input_xml_file": "/home/app/web/api/services/vtb_handler/media/processed/0_sample_GWA10L_JWKIg5o.xml",
    "input_xml_size": 10607,
    "malicious_list": [
      "/home/app/web/api/services/vtb_handler/media/extracted/0_sample_GWA10L_JWKIg5o_10_14471625/string1/string156.pdf",
      "/home/app/web/api/services/vtb_handler/media/extracted/0_sample_GWA10L_JWKIg5o_10_14471625/param7731_xml_12/param7731_10_14471625/file0/file1768.zip",
      "/home/app/web/api/services/vtb_handler/media/extracted/0_sample_GWA10L_JWKIg5o_10_14471625/file1/file3039.rar",
      "/home/app/web/api/services/vtb_handler/media/extracted/0_sample_GWA10L_JWKIg5o_10_14471625/data1/data3689.zip",
      "/home/app/web/api/services/vtb_handler/media/extracted/0_sample_GWA10L_JWKIg5o_10_14471625/data1/data5760.rar",
      "/home/app/web/api/services/vtb_handler/media/extracted/0_sample_GWA10L_JWKIg5o_10_14471625/tag1/tag4375.zip",
      "/home/app/web/api/services/vtb_handler/media/extracted/0_sample_GWA10L_JWKIg5o_10_14471625/tag1/tag3308.exe",
      "/home/app/web/api/services/vtb_handler/media/extracted/0_sample_GWA10L_JWKIg5o_10_14471625/param1/param7198.exe",
      "/home/app/web/api/services/vtb_handler/media/extracted/0_sample_GWA10L_JWKIg5o_10_14471625/param1/param4593.zip",
      "/home/app/web/api/services/vtb_handler/media/extracted/0_sample_GWA10L_JWKIg5o_10_14471625/text1/text1549.zip"
    ],
    "total_archives": 7,
    "malicious_paths": {
      "id": 39,
      "name": "",
      "path": "/home/app/web/media/tmp/179649",
      "type": "directory",
      "children": [
        {
          "id": 39,
          "ext": ".exe",
          "md5": "292ce5c1baa3da54f5bfd847bdd92fa1",
          "name": "param7198.exe",
          "path": "/home/app/web/media/tmp/179649/param7198.exe",
          "sha1": "4d98e3522790a9408e7e85d0e80c3b54a43318e1",
          "size": 108,
          "type": "file",
          "status": true
        },
        {
          "id": 40,
          "ext": ".pdf",
          "md5": "e79b18aeadf57c9d558077c418887686",
          "name": "string156.pdf",
          "path": "/home/app/web/media/tmp/179649/string156.pdf",
          "sha1": "bdc11f1d7d9db7ab99c7005b633cd769270ed074",
          "size": 1744,
          "type": "file",
          "status": true
        },
        {
          "id": 41,
          "ext": ".exe",
          "md5": "292ce5c1baa3da54f5bfd847bdd92fa1",
          "name": "tag3308.exe",
          "path": "/home/app/web/media/tmp/179649/tag3308.exe",
          "sha1": "4d98e3522790a9408e7e85d0e80c3b54a43318e1",
          "size": 108,
          "type": "file",
          "status": true
        }
      ]
    },
    "output_xml_file": "processed/0_sample_GWA10L_JWKIg5o_10_14471625.xml",
    "output_xml_size": 4603,
    "malicious_folder": "/home/app/web/api/services/vtb_handler/media/tmp/179649",
    "malicious_objects": 3
  }
}

