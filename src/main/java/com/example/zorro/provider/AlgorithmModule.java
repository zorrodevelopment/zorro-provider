package com.example.zorro.provider;

import java.security.Provider;

/**
 * Интерфейс «модуля алгоритмов» — каждый модуль реализует {@link #register(Provider)}
 * и кладёт нужные mappings вида {@code MessageDigest.NAME = ClassName} в провайдер.
 *
 * <p>Это идиома Bouncy Castle / Kalkan: главный класс {@code ZorroProvider}
 * перебирает список модулей и вызывает на каждом {@code register(this)}.
 * Удобно расширять — добавил класс, добавил его имя в массив
 * {@code ZorroProvider#MODULES}, и алгоритмы зарегистрированы.
 */
public interface AlgorithmModule {
    /**
     * Регистрирует алгоритмы модуля в указанном провайдере.
     */
    void register(Provider provider);
}
