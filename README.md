# Система сертификации svsp (SCRT-system)

SCRT-system - система, позволяющая производить сертификацию внутри проектов. Используется для возможности реализации криптографических алгоритмов и 
профилактики несанкционированного доступа к сервисам.

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
виде. В папке *sertificates/hes_cert* также создается файл формата *.scrt*, однако этот файл хранит поля сертификата в закрытом виде. Данный файл нельзя перемещать,
изменять, модифицировать так как он используется при проверке валидности сертификатов.

**Установка центра сертификации**

Для установки центра сертификации необходимо на сервер, удовлетворяющий условиям, перечисленным выше, загрузить файл *setup.php* (crt-center в репозитории).
Файл требуется загрузить в корневую директорию сервера. Затем необходимо отправить *GET* запрос к этому файлу с аттрибутами, перечисленными ниже:

-   dbhost - адрес сервера базы данных;
-   dbuser - пользователь базы данных;
-   dbpass - пароль пользователя базы данных;
-   db - имя базы данных;
-   keepass - пароль, передаваемый как атрибут запроса GET для доступа к системе;
-   user - имя пользователя для доступа к системе; 
-   pass - пароль для доступа к системе









