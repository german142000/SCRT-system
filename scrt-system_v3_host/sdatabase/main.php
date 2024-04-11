<?php

class SCRTDatabase {

	public $db;
	private $dbname;

	public function __construct(){
	
		$database_config = array(
			"host" => "193.222.62.126",
			"user" => "services",
			"pass" => "142000",
			"db_name" => "scrtHost_database",
		);
	
		$this->dbname = $database_config["db_name"];
	
		$this->db = mysqli_connect($database_config["host"], $database_config["user"], $database_config["pass"]);
		if($this->db === false){
			die(mysqli_connect_error());
		}
		$dbname = $database_config["db_name"];
		$query = "SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = '$dbname'";
		$result = mysqli_query($this->db, $query);
		if (mysqli_num_rows($result) <= 0) {
    		$query = "CREATE DATABASE $dbname";
			mysqli_query($this->db, $query);
			$query = "USE $dbname";
			mysqli_query($this->db, $query);
		} else {
			$query = "USE $dbname";
			mysqli_query($this->db, $query);
		}
	}

	public function createTable($name, $column_names, $column_types){
		$dbname = $this->dbname;
		$query = "USE $dbname";
		mysqli_query($this->db, $query);
		if(count($column_names) == count($column_types)){
			$ntps = "";
			for($i = 0; $i < count($column_names); $i++){
				$ntps = $ntps.$column_names[$i]." ".$column_types[$i].", ";
			}
			$ntps = substr($ntps, 0, strlen($ntps) - 2);
			$query = "CREATE TABLE $name ($ntps)";
			$result = mysqli_query($this->db, $query);
			if(!$result){
				die(mysqli_error($this->db));
			}
		} else {
			die("the size of \$column_names must match the size of \$column_types");
		}
	}
					
	public function sendSQLRequest($sql){
		$dbname = $this->dbname;
		$query = "USE $dbname";
		mysqli_query($this->db, $query);
		$result = mysqli_query($this->db, $sql);
		if(!$result){
			die(mysqli_error($this->db));
		} else {
			return $result;
		}
	}

}

?>