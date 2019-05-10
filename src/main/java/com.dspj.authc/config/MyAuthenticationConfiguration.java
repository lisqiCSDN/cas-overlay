package com.dspj.authc.config;

import com.dspj.authc.handler.MyAuthenticationHandler;
import org.apereo.cas.authentication.AuthenticationEventExecutionPlan;
import org.apereo.cas.authentication.AuthenticationEventExecutionPlanConfigurer;
import org.apereo.cas.authentication.AuthenticationHandler;
import org.apereo.cas.authentication.principal.DefaultPrincipalFactory;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.services.ServicesManager;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.annotation.Resource;

/**
 * @ClassName: CustomConfiguration
 * @Date: 2019/5/10
 * @describe:
 */
@Configuration("MyAuthenticationConfiguration")
@EnableConfigurationProperties(CasConfigurationProperties.class)
public class MyAuthenticationConfiguration implements AuthenticationEventExecutionPlanConfigurer {

    @Resource
    @Qualifier("servicesManager")
    private ServicesManager servicesManager;

    //注册验证器
    @Bean
    public AuthenticationHandler myAuthenticationHandler() {
        //优先验证
        return new MyAuthenticationHandler(MyAuthenticationHandler.class.getSimpleName(),
                servicesManager, new DefaultPrincipalFactory(), 10);
    }

    //注册自定义认证器
    @Override
    public void configureAuthenticationExecutionPlan(final AuthenticationEventExecutionPlan plan) {
        plan.registerAuthenticationHandler(myAuthenticationHandler());
    }
}
