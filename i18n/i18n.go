//go:build linux

// Copyright 2019 Path Network, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package i18n

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Localizer 国际化本地化器
type Localizer struct {
	lang     string
	messages map[string]string
}

// defaultLocalizer 默认本地化器实例
var defaultLocalizer *Localizer

// supportedLanguages 支持的语言列表
var supportedLanguages = []string{"en", "zh"}

// Init 初始化国际化系统
func Init(lang string) error {
	if lang == "" {
		lang = detectSystemLanguage()
	}

	// 验证语言是否支持
	if !isLanguageSupported(lang) {
		lang = "en" // 默认使用英文
	}

	localizer, err := NewLocalizer(lang)
	if err != nil {
		return fmt.Errorf("failed to initialize localizer: %w", err)
	}

	defaultLocalizer = localizer
	return nil
}

// NewLocalizer 创建新的本地化器
func NewLocalizer(lang string) (*Localizer, error) {
	localizer := &Localizer{
		lang:     lang,
		messages: make(map[string]string),
	}

	if err := localizer.loadMessages(); err != nil {
		return nil, err
	}

	return localizer, nil
}

// loadMessages 加载语言消息文件
func (l *Localizer) loadMessages() error {
	// 获取当前执行文件的目录
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	execDir := filepath.Dir(execPath)
	messageFile := filepath.Join(execDir, "i18n", "locales", l.lang+".json")

	// 如果在执行目录找不到，尝试在源码目录查找
	if _, statErr := os.Stat(messageFile); os.IsNotExist(statErr) {
		// 尝试相对于当前工作目录
		wd, _ := os.Getwd()
		messageFile = filepath.Join(wd, "i18n", "locales", l.lang+".json")
	}

	data, err := os.ReadFile(messageFile)
	if err != nil {
		return fmt.Errorf("failed to read message file %s: %w", messageFile, err)
	}

	if err := json.Unmarshal(data, &l.messages); err != nil {
		return fmt.Errorf("failed to parse message file %s: %w", messageFile, err)
	}

	return nil
}

// T 翻译消息（使用默认本地化器）
func T(key string, args ...interface{}) string {
	if defaultLocalizer == nil {
		return key // 如果未初始化，返回原始key
	}
	return defaultLocalizer.T(key, args...)
}

// T 翻译消息
func (l *Localizer) T(key string, args ...interface{}) string {
	message, exists := l.messages[key]
	if !exists {
		return key // 如果找不到翻译，返回原始key
	}

	if len(args) > 0 {
		return fmt.Sprintf(message, args...)
	}
	return message
}

// GetLanguage 获取当前语言
func GetLanguage() string {
	if defaultLocalizer == nil {
		return "en"
	}
	return defaultLocalizer.lang
}

// detectSystemLanguage 检测系统语言
func detectSystemLanguage() string {
	// 检查环境变量
	for _, env := range []string{"LANG", "LC_ALL", "LC_MESSAGES"} {
		if lang := os.Getenv(env); lang != "" {
			// 提取语言代码（例如：zh_CN.UTF-8 -> zh）
			if parts := strings.Split(lang, "_"); len(parts) > 0 {
				langCode := strings.ToLower(parts[0])
				if isLanguageSupported(langCode) {
					return langCode
				}
			}
		}
	}
	return "en" // 默认英文
}

// isLanguageSupported 检查语言是否支持
func isLanguageSupported(lang string) bool {
	for _, supported := range supportedLanguages {
		if supported == lang {
			return true
		}
	}
	return false
}

// GetSupportedLanguages 获取支持的语言列表
func GetSupportedLanguages() []string {
	return supportedLanguages
}
