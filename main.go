package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
	"unsafe"
)

//export ISCPost
func ISCPost(host *C.char, path *C.char, appKey *C.char, sk *C.char, body *C.char) *C.char {
	// 将 C 字符串转换为 Go 字符串
	goHost := C.GoString(host)
	goPath := C.GoString(path)
	goAppKey := C.GoString(appKey)
	goSK := C.GoString(sk)
	goBody := C.GoString(body)

	fmt.Println("Host:", goHost)
	fmt.Println("Path:", goPath)
	fmt.Println("AppKey:", goAppKey)
	fmt.Println("SK:", goSK)
	fmt.Println("Body:", goBody)

	// 构建 URL
	url := fmt.Sprintf("%s%s", goHost, goPath)

	// 构建签名字符串
	stringToSign := fmt.Sprintf(
		"POST\n*/*\napplication/json\nx-ca-key:%s\n%s",
		goAppKey, goPath,
	)

	// 计算签名
	signature := calculateSignature(goSK, stringToSign)

	// 构建 HTTP 请求
	req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(goBody)))
	if err != nil {
		println(err.Error())
		return nil
	}

	// 设置请求头
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("X-Ca-Key", goAppKey)
	req.Header.Set("X-Ca-Signature", signature)
	req.Header.Set("X-Ca-Signature-Headers", "x-ca-key")

	// 创建一个忽略证书验证的 Transport
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // 忽略证书验证
		},
	}

	// 使用自定义 Transport 创建 http.Client
	client := &http.Client{
		Transport: tr,
		Timeout: 4 * time.Second // 4秒超时时间
	}

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		println(err.Error())
		return nil
	}
	defer resp.Body.Close()

	// 读取响应体
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		println(err.Error())
		return nil
	}

	// 检查 HTTP 状态码
	if resp.StatusCode != http.StatusOK {
		println("statusCode error:", resp.StatusCode)
		return nil
	}

	// 将响应内容转换为 C 字符串并返回
	return C.CString(string(respBody))
}

// calculateSignature 计算签名
func calculateSignature(secret string, stringToSign string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// 主函数仅用于本地测试
func main() {
	// 示例调用（仅本地测试，导出函数会被 C 代码调用）
	// 不建议直接运行 main 时调用导出函数。
	host := os.Args[1]
	appKey := os.Args[2]
	sk := os.Args[3]
	path := "/artemis/api/resource/v1/cameras"
	body := "{\"pageNo\":1 , \"pageSize\":10}"

	// 输出参数用于调试
	fmt.Println("调试信息:")
	fmt.Println("Host:", host)
	fmt.Println("Path:", path)
	fmt.Println("AppKey:", appKey)
	fmt.Println("SK:", sk)
	fmt.Println("Body:", body)

	// 这里进行测试获取监控点信息
	// 调用 ISCPost 函数
	response := ISCPost(C.CString(host), C.CString(path), C.CString(appKey), C.CString(sk), C.CString(body))

	// 打印返回的响应
	if response != nil {
		defer C.free(unsafe.Pointer(response))
		fmt.Println("响应:", C.GoString(response))
	}
}
