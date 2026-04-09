// src/threadpool.cpp
#include "threadpool.h"

ThreadPool::ThreadPool(size_t n) {
    for (size_t i = 0; i < n; ++i)
        workers_.emplace_back([this] {
            while (true) {
                std::function<void()> task;
                {
                    std::unique_lock<std::mutex> lk(mtx_);
                    cv_.wait(lk, [this]{ return stop_ || !tasks_.empty(); });
                    if (stop_ && tasks_.empty()) return;
                    task = std::move(tasks_.front());
                    tasks_.pop();
                }
                task();
            }
        });
}

ThreadPool::~ThreadPool() {
    { std::unique_lock<std::mutex> lk(mtx_); stop_ = true; }
    cv_.notify_all();
    for (auto& t : workers_) t.join();
}