#!/usr/bin/ruby

# Infer entity ids on various platforms.  Requires API access to some platforms
#
# How it works: 
#   Given a url (http://www.foo.com/) and a name (Foo) it will search
#   for entity presences, in the following order, if applicable, in
#
#      - metadata info present in the "head" tag of the url
#        (eg <head><meta property="twitter:site" value="foo"> ... )
#      - link on the website (eg <a href="https://facebook.com/foo">)
#      - text search of the platform api or Google for the name
#
# All of these strategies are confirmed by a backwards link to the original 
# website. (eg https://twitter.com/foo must have a link to http://www.foo.com/)
#
# Usage:
#
# Socializer.configure do |config|
#
##   Twitter - Get your credentials from your app at the Twitter Dev site.
##   Create an app if you don't have one.
#
#   config.twitter_consumer_key    = 'XXXX'
#   config.twitter_consumer_secret = 'XXXX'
#   config.twitter_access_token = 'XXXX'
#   config.twitter_access_token_secret = 'XXXX'
#
##   Facebook - Get your credentials from your app at the Facebook Dev site
#
#   config.facebook_app_secret = 'XXXX'
#   config.facebook_app_id = 'XXXX'
# end
#
# Socializer.find('http://www.google.com/','Google')
#   => {:wikipedia => "http://en.wikipedia.org/wiki/Google",
#        :facebook => "https://www.facebook.com/Google",
#        :twitter => "https://twitter.com/google"}

require 'pp'
require 'mechanize'
require 'twitter'
require 'koala'
require 'uri'
require 'google-search'

module Socializer

  class << self
    attr_accessor :configuration
  end

  def self.configure
    self.configuration ||= Configuration.new
    yield(configuration)
  end
 
  class Configuration
    attr_accessor :facebook_app_secret, :facebook_app_id, :twitter_consumer_key, :twitter_consumer_secret, :twitter_access_token, :twitter_access_token_secret, :agent, :facebook_client, :twitter_client
 
    def initialize
      @facebook_app_secret = nil
      @facebook_app_id = nil
      @twitter_consumer_key = nil
      @twitter_consumer_secret = nil
      @twitter_access_token = nil
      @twitter_access_token_secret = nil
      @agent = Mechanize.new
      @facebook_client = nil
      @twitter_client = nil
    end
  end
  
  def self.find(url,name, *networks)
    pp "find", url,name,*networks
    agent = self.configuration.agent
    sleep 1
    uri = URI(url)
    pp  uri
    if(uri.scheme.match('http') and uri.host)
      uri.host = uri.host.downcase
      uri.path || uri.path = '/' 
      page = nil
      begin
        page = Nokogiri::HTML(agent.get(uri.to_s).body)
      rescue Exception => e
        $stderr.puts "Could get %s" % uri.to_s
        $stderr.puts e.message
        $stderr.puts e.backtrace
        return
      end
    end
    ret = {}
    puts "about to begin"
    if(networks.length == 0 or (networks[0].kind_of?(Array) and networks[0].index('wikipedia') != nil))
      if(wikipedia = find_wikipedia(url,name,page))
        ret['wikipedia'] = wikipedia
      end
    end
    if(networks.length == 0 or (networks[0].kind_of?(Array) and networks[0].index('twitter') != nil))
      if(twitter = find_twitter(url,name,page))
        ret['twitter'] = twitter
      end
    end
    if(networks.length == 0 or (networks[0].kind_of?(Array) and networks[0].index('facebook') != nil))
      if(facebook = find_facebook(url,name,page))
        ret['facebook'] = facebook
      end
    end
    puts "done"
    return ret
  end

  private 

  def self.sigurl(x)
    (x && x.length > 3) || return
    if(!x.match(/^http/))
      x = 'http://' + x
    end
    u = nil
    begin
      u = URI(x)
      u.scheme = 'http'
      u.host = u.host.downcase
      u.host = u.host.sub(/^www\./,'')
      u.fragment = nil
      u.query = nil
      u.path = u.path.sub(/(default|index)\.(html|htm|php|aspx|asp|shtml)$/,'')
      (u.path == nil or u.path == '') and u.path = '/'
      return u.to_s
    rescue
      return
    end
  end

  def twitter_back_check(handle)
    begin
      if(tu = $tw_client.user(handle))    
        return tu.attrs[:entities][:url][:urls][0][:expanded_url]
      end
    rescue Exception => e
      pp e
      return
    end
  end

  def facebook_back_check(handle)
    facebook_client = self.configuration.facebook_client
    begin
      f = facebook_client.get_object(handle)
      return f['website'].split(' ')[0]
    rescue Exception => e
      puts e
      return
    end
  end
  
  def self.find_facebook(url,name,page)
    puts "find_facebook #{name}"
    if(!self.configuration.facebook_client)
      self.setup_facebook
      if(!self.configuration.facebook_client)
        $stderr.puts 'no facebook client'
        return
      end
    end
    facebook_client = self.configuration.facebook_client
    
    fb_new = nil
    begin
      
      # look in fb links listed on the homepage
      page.css("a[href*='facebook.com/']").map {|x| x['href'] }.uniq.compact.each do |fb|
        if(fb['href'])
          fb = fb['href'].downcase
          if(m = fb.match('facebook.com/(\w+)$') and m.length == 2)
            fb_new = m[1]
            if(sigurl(url) == sigurl(facebook_back_check(fb_new)))
              puts "href"
              return fb_new
            end
          end
        end
      end
      
      # look in head metadata
      if(m = page.css('head meta[property="fb:page_id"]') and m.length > 0 and m[0]['content'])
        fb_new = m[0]['content']
        if(sigurl(url) == sigurl(facebook_back_check(fb_new)))
          puts "page_id"
          return fb_new
        end
      end
      
      # search Google, check first result
      
      Google::Search::Web.new(:query => "#{name} facebook").each do |r|      
        if(r.uri and u = URI(r.uri) and u.host.match('facebook.com') and u.path.length > 1)
          fb_new = u.path.split('/').last
          if(sigurl(url) == sigurl(facebook_back_check(fb_new)))
            puts "page_id"
            return fb_new
          end
        end
        break # only try the first one
      end
    
    rescue 
      $stderr.puts "find_facebook fail #{name} #{url}"
    end
    
    # too many false positives, usually subsidiaries in other countries
    # 
    # # search w/ graph api
    # begin
    #   fs = facebook_client.search(name,{:type => 'page'})
    #   fs[0..10].each do |f|
    #     fp = facebook_client.get_object(f['id'])
    #     if(fp['website'] and fp['is_verified'] and fp['link'] and sigurl(fp['website'].split(' ')[0]) == sigurl(url))
    #       puts "graph " + fp['link']
    #       return fp['link']
    #     end
    #   end        
    # rescue Exception => e
    #     pp e
    # end
    return
  end

  def self.find_wikipedia(url,name,page)
    puts "find_wikipedia #{name}"
    agent = self.configuration.agent
    count = 0
    begin
      Google::Search::Web.new(:query => "#{name} wikipedia" ).each do |r|
        count > 10 and break
        count += 1
        r.uri.match('en.wikipedia.org') or next
        p = Nokogiri::HTML(agent.get(r.uri).body)
        if(o = p.css("table.infobox tr:contains('Website') a") and o.length > 0 and sigurl(o[0]['href']) == sigurl(url))
          return r.uri
        end        
      end
    rescue Exception => e
      $stderr.puts "find wikipedia, couldn't get %s" % url
      pp e
      return
    end
    puts "end find_wikipedia"
  end

  def self.find_twitter(url,name,page)
    puts "find_twitter #{name}"
    if(!self.configuration.twitter_client)
      self.setup_twitter
      if(!self.configuration.twitter_client)
        $stderr.puts 'no twitter client'
        return
      end
    end
    twitter_client = self.configuration.twitter_client

    # t_new = nil

    # if(m = page.css('head meta[property="twitter:site"]') and m.length > 0 and m[0]['content'])
    #   t_new = m[0]['content'].sub('@','')
    #   puts "twitter:site " + t_new
    # end
    
    # if(m = page.css('head meta[property="twitter:account_id"]') and m.length > 0 and m[0]['content'])
    #   t_new = m[0]['content']
    #   puts "twitter:account_id " + t_new
    #   # resolve to handle
    # end
    
    page.css("a[href*='twitter.com/']").map {|x| x['href'] }.uniq.compact.each do |twitter|
      if(twitter['href'] and twitter = twitter['href'].sub('#!/','') and m = twitter.match('twitter\.com/([\-\w]+)') and m.length == 2)
        t_new = m[1].downcase
        if(sigurl(url) == sigurl(twitter_back_check(t_new)))
          return t_new
        end
      end
    end

    twitter_client.user_search(name).each do |tu|
      begin
        if(tu['verified'] and sigurl(tu.attrs[:entities][:url][:urls][0][:expanded_url]) == sigurl(url))
          return 'https://twitter.com/' + tu[:screen_name].downcase
        end
      rescue
        
      end
    end
    return
  end

  def self.setup_facebook
    facebook_app_secret = self.configuration.facebook_app_secret
    facebook_app_id = self.configuration.facebook_app_id
    if(facebook_app_secret and facebook_app_id)
      oauth = Koala::Facebook::OAuth.new(facebook_app_id, facebook_app_secret)
      app_token = oauth.get_app_access_token
      self.configuration.facebook_client = Koala::Facebook::API.new(app_token)
    end
  end

  def self.setup_twitter
    twitter_consumer_secret = self.configuration.twitter_consumer_secret
    twitter_consumer_key = self.configuration.twitter_consumer_key
    twitter_access_token = self.configuration.twitter_access_token
    twitter_access_token_secret = self.configuration.twitter_access_token_secret

    if(twitter_consumer_key and twitter_consumer_secret and twitter_access_token and twitter_access_token_secret )
      self.configuration.twitter_client = Twitter::REST::Client.new do |tconfig|
        tconfig.consumer_key = twitter_consumer_key
        tconfig.consumer_secret = twitter_consumer_secret
        tconfig.access_token = twitter_access_token
        tconfig.access_token_secret = twitter_access_token_secret
      end
    else
      $stderr.puts('no configured twitter api')
    end
  end

end


