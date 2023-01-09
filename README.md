# Система сертификации svsp (SCRT-system)

SCRT-system - система, позволяющая производить сертификацию внутри проектов. Используется для возможности реализации криптографических алгоритмов и 
профилактики несанкционированного доступа к сервисам. 
Состоит из связки "*центр сертификации - клиенты*".

# Центр сертификации

Центром сертификации выступает отдельный сервер, который выдает сертификаты и проверяет валидность этих сертификатов по запросам клиентов и других серверов. 

**Условия для создания центра сертификации системы svsp**

Для создания центра сертификации сервер должен поддерживать PHP и MySql. MySql используется для хранения информации о продуктах, которые обслуживаются данной 
системой.

**Устройство центра сертификации svsp**

Центр сертификации состоит из двух модулей - системы создания сертификатов и API для проверки валидности сертификатов. Вся информация между модулями, файлами
центра сертификации передается в зашифрованном виде (за исключением MySql).

![image](https://user-images.githubusercontent.com/77344156/211185025-33e5c872-dd41-49f9-908f-7e24865e8e7f.png)
*Экран входа в систему создания сертификатов*

При создании сертификатов и продуктов указывается два параметра - имя и срок регистрации. Срок регистрации - срок, в течении которого сертификат или продукт 
являются валидными.

При добавлении продукта создается новая строка в базе данных. Имена продуктов должны быть индивидуальными. По истечению срока регистрации продукта все сертификаты,
созданные для этого продукта, считаются аннулированными.

При создании сертификата в закрытой папке *sertificates* создается файл формата *.scrt*, который хранит поля только что созданного сертификата в открытом
виде. Данный файл необходимо будет передать стороне, для которой создавался сертификат. В папке *sertificates/hes_cert* также создается файл формата *.scrt*, 
однако этот файл хранит поля сертификата в закрытом виде. Данный файл нельзя перемещать,
удалять или модифицировать так как он используется при проверке валидности сертификатов.

Открытым ключом сертификата являются два значения - *root* и *prime* - значения, необходимые для поддержания работоспособности алгоритма Диффи - Хеллмана. О том
как получить эти значения - ниже.

**Установка центра сертификации**

Для установки центра сертификации необходимо на сервер, удовлетворяющий условиям, перечисленным выше, загрузить файл *setup.php* (*crt-center* в репозитории).
Файл требуется загрузить в корневую директорию сервера. Затем необходимо отправить *GET* запрос к этому файлу с аттрибутами, перечисленными ниже:

-   dbhost - адрес сервера базы данных;
-   dbuser - пользователь базы данных;
-   dbpass - пароль пользователя базы данных;
-   db - имя базы данных;
-   getpass - пароль, передаваемый как атрибут запроса GET для доступа к системе;
-   user - имя пользователя для доступа к системе; 
-   pass - пароль для доступа к системе

После этого в корневой директории появятся папки с необходимыми файлами, а также файл *index.php*.

# Клиенты

Для проверки сертификатов на клиентской стороне используется библиотека *check_certificate_svsp_certificate_system.js*. В библиотеке определены 4 функции 
для взаимодействия с сертификатом и центрами сертификации. 

**Хранение выданных сертификатов**

Выданные сертификаты центром храняться на сервере в любой папке на сервере (например *cert*). В этой папке должен быть файл *cert.php* (к которому 
обращается библиотека) и папка *cert*, в которой непосредственно хранится открытый сертификат. Во избежании кражи сертификата в папке *cert* необходимо расположить
конфигурационный файл *.htaccess*, в котором нужно запретить доступ к папке из вне.







