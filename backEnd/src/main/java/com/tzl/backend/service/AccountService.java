package com.tzl.backend.service;

import com.baomidou.mybatisplus.extension.service.IService;
import com.tzl.backend.Entity.dto.Account;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface AccountService extends IService<Account>, UserDetailsService {
    Account findAccountByNameOrEmail(String text);
}
