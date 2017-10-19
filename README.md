#### 验证头像是否是同一个人

```go
package main 
import (
	"log"
  	"github.com/zhanghjster/face"
)

func main() {	
  res, err := face.NewCompare(AccessKeyId, AccesskeySecret).Do(first, second)
  if err != nil {
    log.Fatal(err)
  }

  log.Printf("是否相同: %d, 相似程度: %f", res.PairVerifyResult, res.PairVerifySimilarity)
}
```

