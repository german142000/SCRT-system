# Система сертификации svsp (SCRT-system)

SCRT-system - криптосистема, позволяющая производить сертификацию внутри проектов. Используется для профилактики несанкционированного доступа к различной информации.
Основная цель системы - реализация простого и быстрого способа передачи данных по незащищенным сетевым каналам.

Состоит из связки "*центр сертификации - хост сервер - клиенты*".

Хост сервер и центр сертификации написаны на PHP. Клиенты написаны на java и js. На языке java существует две версии - для android и версия для остальных приложений, независящая от android sdk. Клиенты в будущем могут пополняться.

# Центр сертификации

Центром сертификации выступает отдельный сервер, который выдает сертификаты и проверяет валидность этих сертификатов по запросам клиентов. 

**Установка и настройка центра сертификации**

Для создания центра сертификации сервер должен поддерживать PHP и иметь модуль openssl. Чтобы центр сертификации заработал, необходимо расположить директорию "*scrt-system_v3*" в любом месте сервера,
но желательно в корне. Эта папка должна быть доступна любой машине из сети. Впоследствии путь к директориям SCRT-system указывается в конфигурационных полях на клиентах.

После загрузки файлов на сервер вам необходимо изменить файл "*config.php*" из папки "*scrt-system_v3*". Он содержит четыре поля:

-   version - версия центра сертификации, это поле нельзя менять;
-   scrt_directory - путь к директории центра сертификации на сервере, здесь вам необходимо задать полный путь;
-   keyBits - размер ключа, используется во время генерации сертификата, устанавливается по требованиям;
-   password - пароль для администрирования;

После изменения файла вам необходимо закрыть доступ к папке "*certificates*" из "*scrt-system_v3*". 
НЕ ЗАБУДЬТЕ ЭТО СДЕЛАТЬ, иначе данные, передающиеся с ипользование SCRT-system будут скомпрометированы.

**Сертификаты**

Данная версия пока что не содержит UI панель для управления сертификатами. Все действия по перемещению и удалению файлов с сертификатами производятся из терминала.

Для создания нового сертификата вам необходимо отправить GET-запрос к файлу "*createCertificate.php*" с определенными параметрами. 
Рекомендуется это делать с использованием протокола HTTPS, так как пароль передается в открытом виде.

-   product - название продукта, параметер выполняет информативную роль;
-   month - количество месяцев, в течение которых сертификат действителен, рекомендуется устанавливать не больше одного;
-   keeper - IP адрес хоста, для которого генерируется сертификат, требуется указывать именно IP адрес вида "0.0.0.0";
-   password - пароль для администрирования, который был указан в файле "*config.php*";

После выполнения запроса на запрашиваемой странице должен появится идентификатор только что созданного сертификата. Его файлы будут лежать по пути "*scrt-system_v3/certificates/{идентификатор сертификата}*".
Каждый сертификат состоит из трёх файлов - "*param.json*", "*public_key.pem*", "*private_key.pem*". Чтобы сертификат был действительным в течении выбраного периода, в этой папке должны лежать файлы "*param.json*" и "*public_key.pem*".
По истечению срока сертификата его директорию можно удалить. Файл "*private_key.pem*" необходимо будет расположить на хост сервере, после чего можно будет удалить.

# Хост сервер

Хост сервер - машина, на которой расположен продукт, требующий защищенной передачи данных между клиентами и сервером. Для этой машины и выпускается сертификат.
В поле keeper при выпуске сертификата должен указываться IP этой же машины. Непосредственно на неё должна загружаться приватная часть сертификата.

**Установка и настройка**

Для установки требуется PHP с модулем openssl. Чтобы хост заработал, необходимо расположить директорию "*scrt-system_v3_host*" в любом месте сервера,
но желательно в корне. Эта папка должна быть доступна любой машине из сети. В последствии путь к директориям SCRT-system указывается в конфигурационных полях на клиентах.

После загрузки файлов на сервер вам необходимо изменить файл "*config.php*" из папки "*scrt-system_v3_host*". Он содержит три поля:

-   version - версия центра сертификации, это поле нельзя менять;
-   scrt_directory - путь к директории scrt хоста на сервере, здесь вам необходимо задать полный путь;
-   password - пароль для администрирования;

После изменения файла вам необходимо закрыть доступ к папке "*certificate*" из "*scrt-system_v3_host*". 
НЕ ЗАБУДЬТЕ ЭТО СДЕЛАТЬ, иначе данные, передающиеся с ипользование SCRT-system будут скомпрометированы. 
Также следует установить задачу с использованием crontab (на Unix системах) для своевременной отчистки директории "*sessions*".

**Сертификат**

При создании сертификата на сервере сертификации доступно три файла. 
Для привязки вновь созданного сертификата к хосту в папке "*certificate*" необходимо расположить файлы "*param.json*" и "*private_key.pem*".
Пожалуйста, убедитесь что к этой папке нет доступа из сети.

**API**

Установив хост сервер вы можете использовать его функционал. Поскольку одна из целей этой библиотеки - простота - API имеет всего две функции.
Эти функции прописаны в файле "*packs.php*" в папке "*scrt-system_v3_host*". При написании PHP скрипта вам необходимо подключить этот файл. 
При использовании SCRT-system запрещено использовать в скрипте любые функции вывода. 
Если вы используете вывод ошибок в PHP, вам необходимо для начала исправить все ошибки скрипта (если они есть), после чего скрипт с использованием SCRT-system отработает правильно.

`function getData()`

Возвращает ассоциативный массив с двумя праметрами:

- data - расшифрованная информация, полученная с клиента;
- session - идентификатор scrt сессии;

`function sendData($data, $session)`

Отправляет данные клиенту:

- $data - данные, которые необходимо передать клиенту;
- $session - идентификатор scrt сессии, полученный из массива, возвращаемого функцией `getData()`;

# Клиенты

**Java клиенты**

Как указано выше - существует два Java клиента, идентичных по функционалу. Оба клиента зависят от [`JSON Simple`](https://github.com/fangyidong/json-simple) и [`aes-everywhere`](https://github.com/mervick/aes-everywhere/tree/master).

Клиенты имеют определение класса `SCRT_config`, поля которого необходимо менять для корректного подключения к scrt хосту (я знаю что это неудобно, я изменю это в будущих обновлениях).
Этот класс имеет следующие поля:

- scrt_version - версия центра сертификации, это поле нельзя менять;
- scrt_cert_address - путь к центру сертификации с абсолютным путём к папке "*scrt-system_v3*";
- scrt_host_address - путь к scrt хосчту с абсолютным путём к папке "*scrt-system_v3_host*";
- keeper - IP адрес хоста, к которому будет обращаться клиент;

Определения класса расположены в строках 112-114 обоих клиентов.

Для установки соединения с хостом необходимо создать объект класса `SCRT_session`. Этот класс имеет следующие функции:

- `public SCRT_session()` - конструктор, не принимает аргументов, возвращает объект `SCRT_session`;
- `public boolean getErrorStatus()` - возвращает `true` если в процессе инициализации объекта возникает ошибка, иначе `false`;
- `public String getError()` - возвращает описание ошибки в виде строки;
- `public SCRT_pack sendData(String url, String data)` - отправляет на хост данные, переданные в виде строки через параметр `data` по адресу `url`, ожидается,
что файл по адресу обрабатывает данные с помощью функций "*packs.php*" из директории "*scrt-system_v3_host*", в другом случае поведение не определенно, возвращает объект `SCRT_pack`, который возвращает ответ сервера в расшифрованном виде либо ошибку;

Класс `SCRT_pack` - специальный класс, который позволяет получит как данные, так и ошибку. Имеет в себе только два публичных поля:

- `boolean error` - возвращает `true` если в процессе получения ответа возникает ошибка, иначе `false`;
- `String data` - если `error` равен `true` - возвращает текст ошибки, иначе - расшифрованный ответ от хоста;

`Main.java`
```java
public class Main {
    public static void main(String[] args) {
        SCRT_session ss = new SCRT_session(); //Инициализация SCRT_session
        while(ss.getErrorStatus() && ss.getError().equals("server don't trust. try to create a new session")){
            ss = new SCRT_session(); //Если происходит ошибка, инициализируем SCRT_session снова
        }
        System.out.println("server trust, enter data");
        Scanner scanner = new Scanner(System.in);
        while(true){
            String input = scanner.nextLine();
            System.out.println(ss.sendData("http://127.0.0.1/test.php", input).data); //Отправка запроса, вывод ответа в консоль
        }
        scanner.close();
    }
}
```

`test.php`
```php
include("scrt-system_v3_host/packs.php"); //Подключение SCRT-system
$resp = getData(); //Получение информации
$sum = $resp['data']." edited"; //Изменение информации
sendData($sum, $resp['session']); //Отправка
```

**Js клиент**

Этот клиент также имеет конфиг, расположенный в начале файла. Обладает теме же полями, что и Java клиенты.
В это клиенте используется функциональная парадигма, состоящая из двух функций:

- `function handshake()` - функция, выполняющая инициализацию соединения и сессии, возвращает `false` в случае ошибки;
- `function sendData(url, data)` - отправляет на хост данные, переданные в виде строки через параметр `data` по адресу `url`, ожидается,
что файл по адресу обрабатывает данные с помощью функций "*packs.php*" из директории "*scrt-system_v3_host*", в другом случае поведение не определенно, возвращает отправленные сервером данные в виде строки;

```javascript
handshake(); //Инициализация
console.log(sendData("http://127.0.0.1/test.php", "data")); //Отправка информации, вывод ответа в консоль
```

# Поддержка проекта

Всегда буду рад обратной связи на тему багов.

Как писалось выше, возможно будут новые клиенты (уже есть новый на c++).
