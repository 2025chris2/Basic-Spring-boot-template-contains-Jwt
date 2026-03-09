package com.tzl.backend.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.tzl.backend.Entity.dto.Account;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface AccountMapper extends BaseMapper<Account> {
    public Account findAccountByNameOrEmail(String text);
}
