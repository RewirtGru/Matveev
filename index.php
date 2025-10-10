<?php
session_start();
$dbFile=__DIR__."/data.sqlite";
$dsn="sqlite:".$dbFile;
try{$pdo=new PDO($dsn);$pdo->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);}catch(Exception $e){die("DB error");}
$pdo->exec("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, created_at TEXT NOT NULL)");
function post($k){return isset($_POST[$k])?trim($_POST[$k]):"";}
$errors=[];$messages=[];
if(isset($_GET["logout"])){session_destroy();header("Location: index.php");exit;}
if($_SERVER["REQUEST_METHOD"]==="POST"){
    if(isset($_POST["action"])&&$_POST["action"]==="register"){
        $u=post("username");$p=post("password");$p2=post("password2");
        if($u===""||$p===""){$errors[]="Заполните все поля";}
        if($p!==$p2){$errors[]="Пароли не совпадают";}
        if(!$errors){
            try{
                $hash=password_hash($p,PASSWORD_DEFAULT);
                $st=$pdo->prepare("INSERT INTO users(username,password,created_at) VALUES(?,?,datetime('now'))");
                $st->execute([$u,$hash]);
                $messages[]="Регистрация успешна. Теперь войдите.";
            }catch(Exception $e){
                $errors[]="Имя уже занято";
            }
        }
    }elseif(isset($_POST["action"])&&$_POST["action"]==="login"){
        $u=post("username");$p=post("password");
        if($u===""||$p===""){$errors[]="Заполните все поля";}
        if(!$errors){
            $st=$pdo->prepare("SELECT id,username,password FROM users WHERE username=?");
            $st->execute([$u]);
            $user=$st->fetch(PDO::FETCH_ASSOC);
            if($user&&password_verify($p,$user["password"])){
                $_SESSION["user_id"]=$user["id"];$_SESSION["username"]=$user["username"];
                header("Location: index.php");exit;
            }else{$errors[]="Неверные логин или пароль";}
        }
    }
}
$logged=isset($_SESSION["user_id"]);
?><!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Авторизация</title>
<style>
body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,Noto Sans,sans-serif;background:#f6f7fb;color:#111}
.nav{position:sticky;top:0;background:#111;color:#fff;padding:12px 20px;display:flex;gap:16px;align-items:center}
.nav a{color:#fff;text-decoration:none;padding:8px 12px;border-radius:6px}
.nav a:hover{background:rgba(255,255,255,.1)}
.wrap{max-width:960px;margin:32px auto;padding:0 16px}
.card{background:#fff;border:1px solid #e6e6ef;border-radius:12px;padding:20px;margin-bottom:20px;box-shadow:0 1px 2px rgba(0,0,0,.04)}
h1{font-size:22px;margin:0 0 12px}
form{display:grid;gap:12px}
input[type=text],input[type=password]{width:100%;padding:10px 12px;border:1px solid #d5d7e1;border-radius:8px;font-size:16px}
button{padding:10px 14px;border:0;border-radius:8px;background:#111;color:#fff;font-weight:600;cursor:pointer}
button:hover{opacity:.9}
.msg{padding:10px 12px;border-radius:8px;background:#eef7ff;border:1px solid #cfe3ff}
.err{padding:10px 12px;border-radius:8px;background:#ffecec;border:1px solid #ffbcbc}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:20px}
@media(max-width:800px){.grid{grid-template-columns:1fr}}
.small{font-size:14px;color:#666}
</style>
</head>
<body>
<div class="nav">
<a href="index.php">Главная</a>
<?php if(!$logged): ?>
<a href="#login">Войти</a>
<a href="#register">Регистрация</a>
<?php else: ?>
<span>Привет, <?php echo htmlspecialchars($_SESSION["username"]); ?></span>
<a href="?logout=1">Выйти</a>
<?php endif; ?>
</div>
<div class="wrap">
<div class="card">
<h1>Главная</h1>
<p class="small">Простой пример регистрации и входа на PHP (SQLite, сессии, password_hash).</p>
</div>
<?php if($messages): ?>
<div class="card msg"><?php echo implode("<br>",array_map("htmlspecialchars",$messages)); ?></div>
<?php endif; ?>
<?php if($errors): ?>
<div class="card err"><?php echo implode("<br>",array_map("htmlspecialchars",$errors)); ?></div>
<?php endif; ?>
<?php if($logged): ?>
<div class="card">
<h1>Вы вошли</h1>
<p>Ваш логин: <b><?php echo htmlspecialchars($_SESSION["username"]); ?></b></p>
</div>
<?php else: ?>
<div class="grid">
<div class="card" id="login">
<h1>Войти</h1>
<form method="post" action="index.php#login" autocomplete="on">
<input type="hidden" name="action" value="login">
<input type="text" name="username" placeholder="Логин">
<input type="password" name="password" placeholder="Пароль">
<button type="submit">Войти</button>
</form>
</div>
<div class="card" id="register">
<h1>Регистрация</h1>
<form method="post" action="index.php#register" autocomplete="off">
<input type="hidden" name="action" value="register">
<input type="text" name="username" placeholder="Логин">
<input type="password" name="password" placeholder="Пароль">
<input type="password" name="password2" placeholder="Повторите пароль">
<button type="submit">Зарегистрироваться</button>
</form>
</div>
</div>
<?php endif; ?>
</div>
</body>
</html>
